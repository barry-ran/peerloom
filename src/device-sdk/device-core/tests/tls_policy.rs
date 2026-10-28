//! Linux 系统 CA 路径在独立子进程注入，避免修改并行测试进程的全局环境。
//! 验证相同可信 CA 下，HTTPS/WSS 接受正确 SAN，拒绝错误 SAN。
#![cfg(target_os = "linux")]
use device_core::{
    identity::{IdempotencyKey, IdentityClient, IdentityError, Platform, RegistrationRequest},
    signaling::{SignalClient, SignalError},
};
use device_storage::SecretString;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::{process::Command, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn tls_policy_child() {
    let Ok(origin) = std::env::var("PEERLOOM_TLS_TEST_ORIGIN") else {
        return;
    };
    let valid = std::env::var("PEERLOOM_TLS_TEST_VALID").unwrap() == "yes";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // Even explicit development mode must not relax HTTPS certificate checks.
        let client = IdentityClient::new(&origin, true, Duration::from_secs(3)).unwrap();
        let request = RegistrationRequest {
            application_id: uuid::Uuid::new_v4().to_string(),
            platform: Platform::Linux,
            installation_public_key: "test".into(),
            registration_grant: SecretString::new("reg_test".into()),
            sdk_version: "test".into(),
            metadata: Default::default(),
        };
        let http = client.register(&request, &IdempotencyKey::random()).await;
        if valid {
            assert!(
                matches!(http, Err(IdentityError::Server { status: 401, .. })),
                "HTTPS must reach HTTP policy over verified TLS: {http:?}"
            );
        } else {
            assert!(
                matches!(http, Err(IdentityError::Transport)),
                "wrong SAN must fail TLS: {http:?}"
            );
        }
        let wss = SignalClient::connect(&client, &SecretString::new("dev_test".into())).await;
        if valid {
            assert!(
                matches!(wss, Err(SignalError::AuthorizationRejected)),
                "WSS must reach HTTP policy over verified TLS"
            );
        } else {
            assert!(
                matches!(wss, Err(SignalError::Transport)),
                "wrong SAN must fail WSS TLS"
            );
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_and_wss_share_os_trust_and_hostname_policy() {
    for valid in [true, false] {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![
            if valid {
                "127.0.0.1"
            } else {
                "wrong.example.invalid"
            }
            .into(),
        ])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let tls = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket))
                    .await
                    .unwrap();
                if !valid {
                    assert!(tls.is_err(), "wrong SAN handshake must not succeed");
                    continue;
                }
                let mut tls = tls.unwrap();
                let mut request = vec![0; 8192];
                let mut used = 0;
                while !request[..used].windows(4).any(|x| x == b"\r\n\r\n") {
                    let count = tokio::time::timeout(
                        Duration::from_secs(5),
                        tls.read(&mut request[used..]),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert!(count > 0 && used + count < request.len());
                    used += count;
                }
                let body = r#"{"code":"UNAUTHORIZED"}"#;
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                tls.write_all(response.as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            }
        });
        let dir = std::env::temp_dir().join(format!("peerloom-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        let status = tokio::task::spawn_blocking(move || {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tls_policy_child", "--nocapture"])
                .env("SSL_CERT_FILE", ca_path)
                .env("SSL_CERT_DIR", &dir)
                .env("PEERLOOM_TLS_TEST_ORIGIN", origin)
                .env("PEERLOOM_TLS_TEST_VALID", if valid { "yes" } else { "no" })
                .status()
                .inspect(|_| {
                    std::fs::remove_dir_all(dir).unwrap();
                })
        })
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
        server.await.unwrap();
    }
}
