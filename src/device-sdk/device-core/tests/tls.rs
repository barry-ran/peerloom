//! 在真实 TLS handshake 中验证 HTTP 与 WSS 均拒绝未经信任的自签证书。
use device_core::{
    identity::{IdempotencyKey, IdentityClient, Platform, RegistrationRequest},
    signaling::SignalClient,
};
use device_storage::SecretString;
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
async fn untrusted_server() -> (IdentityClient, tokio::task::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("https://{}", listener.local_addr().unwrap()),
        false,
        Duration::from_secs(3),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(4), acceptor.accept(socket))
                .await
                .expect("TLS handshake deadline")
                .is_err(),
            "untrusted certificate must not establish TLS"
        );
    });
    (client, task)
}
#[tokio::test]
async fn http_rejects_untrusted_certificate() {
    let (client, task) = untrusted_server().await;
    let request = RegistrationRequest {
        application_id: uuid::Uuid::new_v4().to_string(),
        platform: Platform::Linux,
        installation_public_key: "test".into(),
        registration_grant: SecretString::new("reg_test".into()),
        sdk_version: "test".into(),
        metadata: Default::default(),
    };
    assert!(
        client
            .register(&request, &IdempotencyKey::random())
            .await
            .is_err()
    );
    task.await.unwrap();
}
#[tokio::test]
async fn wss_rejects_untrusted_certificate() {
    let (client, task) = untrusted_server().await;
    assert!(
        SignalClient::connect(&client, &SecretString::new("dev_test".into()))
            .await
            .is_err()
    );
    task.await.unwrap();
}
