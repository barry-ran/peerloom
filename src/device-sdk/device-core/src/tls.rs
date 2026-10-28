//! HTTPS 与 WSS 共用操作系统证书策略；绝不跳过证书或主机名校验。
//! 创建可能读取系统信任库；同步工厂必须在非 UI/网络执行器上调用。
use std::sync::Arc;

pub(crate) fn client_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    // Android requires a matching Kotlin verifier and initialized JVM/context.
    // Until the JNI adapter exists, fail explicitly rather than panic or weaken TLS.
    #[cfg(target_os = "android")]
    {
        Err(rustls::Error::General(
            "Android TLS adapter is not initialized/supported".into(),
        ))
    }
    #[cfg(not(target_os = "android"))]
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
