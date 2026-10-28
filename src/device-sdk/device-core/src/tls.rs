//! HTTPS 与 WSS 共用操作系统证书策略；绝不跳过证书或主机名校验。
//! 创建可能读取系统信任库；同步工厂必须在非 UI/网络执行器上调用。
use std::sync::Arc;

pub(crate) fn client_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    #[cfg(target_os = "android")]
    if !ANDROID_INITIALIZED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(rustls::Error::General(
            "Android TLS is not initialized".into(),
        ));
    }
    {
        use rustls_platform_verifier::BuilderVerifierExt;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

#[cfg(target_os = "android")]
static ANDROID_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "android")]
pub fn initialize_android(
    env: &mut jni::Env<'_>,
    context: jni::objects::JObject<'_>,
) -> Result<(), jni::errors::Error> {
    rustls_platform_verifier::android::init_with_env(env, context)?;
    ANDROID_INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}
