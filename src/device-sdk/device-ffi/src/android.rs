//! Same Rust link image as device-core/verifier: no second verifier singleton in another DSO.
use std::ffi::c_void;
/// # Safety
/// env/context are live JNI arguments on the calling JVM-attached thread; context is Application.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_android_tls_initialize(env: *mut c_void, context: *mut c_void) -> u32 {
    if env.is_null() || context.is_null() {
        return 1;
    }
    // SAFETY: JNI wrapper passes its current Env and a local Application context reference.
    let mut unowned = unsafe { jni::EnvUnowned::from_raw(env.cast()) };
    let outcome = unowned
        .with_env(|env| {
            let context = unsafe { jni::objects::JObject::from_raw(env, context.cast()) };
            device_core::initialize_android_tls(env, context)
        })
        .into_outcome();
    match outcome {
        jni::Outcome::Ok(()) => 0,
        _ => 255,
    }
}
