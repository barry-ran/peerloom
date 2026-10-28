//! 托管ICE HTTP客户端契约；真实coturn与授权会话另有显式集成目标。
use device_core::identity::{IdentityClient, IdentityError};
use device_storage::SecretString;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const ID: &str = "00000000-0000-0000-0000-000000000001";
async fn server(
    status: u16,
    body: String,
    extra: &str,
) -> (IdentityClient, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        true,
        Duration::from_secs(2),
    )
    .unwrap();
    let extra = extra.to_owned();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut part = [0; 1024];
            let n = socket.read(&mut part).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&part[..n]);
            assert!(request.len() < 8192);
            if request.windows(4).any(|x| x == b"\r\n\r\n") {
                break;
            }
        }
        socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",body.len()).as_bytes()).await.unwrap();
        String::from_utf8(request).unwrap()
    });
    (client, task)
}
#[tokio::test]
async fn session_endpoint_uses_bearer_and_preserves_empty_configuration() {
    let body = json!({"session_id":ID,"negotiation_generation":1,"ice_servers":[]}).to_string();
    let (client, task) = server(200, body, "").await;
    let secret = SecretString::new(format!("dev_{}", "a".repeat(43)));
    let value = client.session_ice_servers(ID, &secret).await.unwrap();
    assert!(value.into_live_servers().unwrap().is_empty());
    let request = task.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET /v1/device-sessions/{ID}/ice-servers HTTP/1.1\r\n"
    )));
    assert!(
        request
            .to_lowercase()
            .contains(&format!("authorization: bearer dev_{}", "a".repeat(43)))
    );
    assert!(!request.lines().next().unwrap().contains("dev_"));
}
#[tokio::test]
async fn denial_is_not_converted_into_empty_ice_and_redirect_is_not_followed() {
    let secret = SecretString::new(format!("dev_{}", "a".repeat(43)));
    for status in [401, 403, 429, 503] {
        let (client, task) =
            server(status, json!({"code":"RELAY_UNAVAILABLE"}).to_string(), "").await;
        assert!(
            matches!(client.session_ice_servers(ID,&secret).await,Err(IdentityError::Server{status:code,..}) if code==status)
        );
        task.await.unwrap();
    }
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!(
        "Location: http://{}/capture\r\n",
        destination.local_addr().unwrap()
    );
    let (client, task) = server(302, "{}".into(), &location).await;
    assert!(matches!(
        client.session_ice_servers(ID, &secret).await,
        Err(IdentityError::Server { status: 302, .. })
    ));
    task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn invalid_session_and_wrong_audience_reject_before_network() {
    let client = IdentityClient::new("http://127.0.0.1:9", true, Duration::from_secs(1)).unwrap();
    assert!(matches!(
        client
            .session_ice_servers(ID, &SecretString::new(format!("svc_{}", "a".repeat(43))))
            .await,
        Err(IdentityError::InvalidRequest)
    ));
    assert!(matches!(
        client
            .session_ice_servers(
                "../../device-self",
                &SecretString::new(format!("dev_{}", "a".repeat(43)))
            )
            .await,
        Err(IdentityError::InvalidRequest)
    ));
}
