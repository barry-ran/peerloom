//! Windows DPAPI secure-store example: never falls back to memory/plaintext persistence.
//! Secrets and message contents come from stdin, not command-line arguments/logs.
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("This example requires Windows CurrentUser DPAPI.");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
mod windows {
    use device_core::{
        identity::{
            IdempotencyKey, IdentityClient, IdentitySession, Platform, RegistrationRequest,
        },
        sdk::{DeviceSdk, SdkConfig, SdkEvent},
    };
    use device_storage::{SecretString, WindowsDpapiStore};
    use serde::Deserialize;
    use std::{io::Read, sync::Arc, time::Duration};
    use zeroize::{Zeroize, Zeroizing};
    type Error = Box<dyn std::error::Error + Send + Sync>;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RegistrationInput {
        registration_grant: String,
        installation_public_key: String,
        idempotency_key: String,
    }
    impl Drop for RegistrationInput {
        fn drop(&mut self) {
            self.registration_grant.zeroize();
        }
    }
    fn input() -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::stdin().take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("输入过大 / Input exceeds 64 KiB".into());
        }
        Ok(bytes)
    }
    pub fn run() -> Result<(), Error> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        let valid = matches!(
            args.first().map(String::as_str),
            Some("register" | "status")
        ) && args.len() == 1
            || matches!(args.first().map(String::as_str), Some("send" | "listen"))
                && args.len() == 2;
        if !valid {
            return Err("用法 / Usage: windows_secure_peer register|status|send <target-id>|listen <allowed-source-id>".into());
        }
        let origin = std::env::var("PEERLOOM_ORIGIN")?;
        let application = std::env::var("PEERLOOM_APPLICATION_ID")?;
        let directory = std::env::var("PEERLOOM_LOCK_DIR")?;
        let mut config = SdkConfig::new(origin.clone(), application.clone());
        config.development_loopback = std::env::var("PEERLOOM_DEV_LOOPBACK").as_deref() == Ok("1");
        let bytes = if args[0] == "register" || args[0] == "send" {
            input()?
        } else {
            Zeroizing::new(Vec::new())
        };
        let store = Arc::new(WindowsDpapiStore::new(directory.into())?);
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            if args[0] == "register" || args[0] == "status" {
                let client = IdentityClient::new(&origin, config.development_loopback, Duration::from_secs(10))?;
                let mut session = IdentitySession::load(client, application.clone(), store).await?;
                if args[0] == "register" {
                    let mut registration: RegistrationInput = serde_json::from_slice(&bytes)?;
                    let request = RegistrationRequest { application_id: application, platform: Platform::Windows,
                        installation_public_key: std::mem::take(&mut registration.installation_public_key),
                        registration_grant: SecretString::new(std::mem::take(&mut registration.registration_grant)),
                        sdk_version: env!("CARGO_PKG_VERSION").into(), metadata: Default::default() };
                    session.register(request, IdempotencyKey::new(std::mem::take(&mut registration.idempotency_key))?).await?;
                    if session.needs_persistence() { return Err("身份未持久化；停止，不回退内存 / Identity persistence pending; stopping".into()); }
                }
                let device = session.device_self().await?;
                println!("device_id={}", device.device_id);
                return Ok::<(), Error>(());
            }
            let mut sdk = DeviceSdk::load(config, store).await?;
            println!("device_id={}", sdk.device_id());
            let result = tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    match sdk.next_event().await.ok_or("SDK已关闭 / SDK closed")? {
                        SdkEvent::Online if args[0] == "send" => sdk.connect(&args[1]).await?,
                        SdkEvent::Online | SdkEvent::Offline => (),
                        SdkEvent::IncomingConnection { session_id, source_device_id } => {
                            if args[0] == "listen" && source_device_id == args[1] { sdk.accept(&session_id).await?; }
                            else { sdk.reject(&session_id).await?; }
                        }
                        SdkEvent::ConnectionReady(mut connection) => {
                            if args[0] == "send" {
                                connection.send(&bytes).await?;
                                let reply = connection.receive().await?;
                                if reply != *bytes { return Err("回显不匹配 / Echo mismatch".into()); }
                                println!("已验证回显 / Echo verified: {} bytes", reply.len());
                                connection.send(b"peerloom-example-ack").await?;
                                // Wait for peer close so a queued SCTP ACK is not discarded.
                                let _ = tokio::time::timeout(Duration::from_secs(5), connection.receive()).await;
                            } else {
                                let message = connection.receive().await?;
                                connection.send(&message).await?;
                                if connection.receive().await? != b"peerloom-example-ack" { return Err("回显确认无效 / Invalid echo acknowledgement".into()); }
                                println!("已回显 / Echo sent: {} bytes", message.len());
                            }
                            connection.close().await?;
                            return Ok::<(), Error>(());
                        }
                        SdkEvent::IdentityPersistencePending => return Err("安全存储失败；停止，不回退 / Secure persistence failed; stopping".into()),
                        SdkEvent::Stopped(error) | SdkEvent::ConnectionClosed { reason: error, .. } | SdkEvent::ConnectionRequestFailed { reason: error, .. } => return Err(error.into()),
                    }
                }
            }).await;
            sdk.close().await;
            result.map_err(|_| "示例60秒截止 / Example 60-second deadline")?
        })
    }
}
#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = windows::run() {
        eprintln!("示例失败；无内存/明文后备 / Failed; no memory/plaintext fallback: {error}");
        std::process::exit(1);
    }
}
