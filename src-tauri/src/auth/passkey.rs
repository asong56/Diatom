use anyhow::Result;

/// Reason biometric/platform auth is unavailable. Sent to the frontend so it can
/// display a context-appropriate message rather than silently pass or fail.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometricUnavailableReason {
    /// No authentication hardware present on this device.
    NoHardware,
    /// Hardware present but no credentials enrolled (e.g. Touch ID not set up).
    NotEnrolled,
    /// Linux: no supported auth mechanism installed (fprintd / zenity / kdialog).
    LinuxNoDaemon,
    /// Platform check itself failed unexpectedly.
    CheckFailed,
}

/// Check if platform biometric authentication is available.
pub fn is_biometric_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos_biometric_available()
    }

    #[cfg(target_os = "windows")]
    {
        windows_hello_available()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        linux_biometric_available()
    }
}

/// Return the reason auth is unavailable, or None if it is available.
pub fn biometric_unavailable_reason() -> Option<BiometricUnavailableReason> {
    if is_biometric_available() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new(
            "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
        )
        .exists()
        {
            return Some(BiometricUnavailableReason::NotEnrolled);
        }
        return Some(BiometricUnavailableReason::NoHardware);
    }
    #[cfg(target_os = "windows")]
    {
        if std::path::Path::new(r"C:\Windows\System32\webauthn.dll").exists() {
            return Some(BiometricUnavailableReason::NotEnrolled);
        }
        return Some(BiometricUnavailableReason::NoHardware);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        return Some(BiometricUnavailableReason::LinuxNoDaemon);
    }
}

/// Prompt the user for biometric / platform authentication.
///
/// `reason` is shown to the user in the OS dialog.
///
/// Returns `Ok(true)` if authenticated, `Ok(false)` if denied/cancelled,
/// `Err` if the API itself failed.
pub async fn authenticate(reason: &str) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        macos_authenticate(reason).await
    }

    #[cfg(target_os = "windows")]
    {
        windows_authenticate(reason).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        linux_authenticate(reason).await
    }
}

#[cfg(target_os = "macos")]
fn macos_biometric_available() -> bool {
    std::path::Path::new(
        "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
    )
    .exists()
}

#[cfg(target_os = "macos")]
async fn macos_authenticate(reason: &str) -> Result<bool> {
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};

    let reason_owned = reason.to_owned();
    let result = tokio::task::spawn_blocking(move || -> bool {
        let context = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        let mut error = std::ptr::null_mut();

        let can_evaluate = unsafe { context.canEvaluatePolicy_error(policy, &mut error) };
        if !can_evaluate {
            tracing::debug!("passkey: LAContext canEvaluatePolicy returned false");
            let policy_pw = LAPolicy::DeviceOwnerAuthentication;
            let can_pw =
                unsafe { context.canEvaluatePolicy_error(policy_pw, &mut std::ptr::null_mut()) };
            if !can_pw {
                tracing::warn!(
                    "passkey: no auth hardware or enrolled credentials on macOS — denying"
                );
                return false;
            }
        }

        let sema = std::sync::Arc::new(std::sync::Mutex::new(false));
        let sema2 = sema.clone();
        let condvar = std::sync::Arc::new(std::sync::Condvar::new());
        let condvar2 = condvar.clone();

        let reason_ns = NSString::from_str(&reason_owned);
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                policy,
                &reason_ns,
                objc2::block2::RcBlock::new(
                    move |success: bool, _err: *mut objc2_foundation::NSError| {
                        let mut val = sema2.lock().unwrap();
                        *val = success;
                        condvar2.notify_one();
                    },
                ),
            );
        }

        let val = sema.lock().unwrap();
        let (result, _) = condvar
            .wait_timeout(val, std::time::Duration::from_secs(60))
            .unwrap();
        *result
    })
    .await
    .unwrap_or(false);

    Ok(result)
}

#[cfg(target_os = "windows")]
fn windows_hello_available() -> bool {
    std::path::Path::new(r"C:\Windows\System32\webauthn.dll").exists()
}

#[cfg(target_os = "windows")]
async fn windows_authenticate(reason: &str) -> Result<bool> {
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows_core::HSTRING;

    let reason_hs = HSTRING::from(reason);
    let result = tokio::task::spawn_blocking(move || -> bool {
        let async_op =
            UserConsentVerifier::RequestVerificationAsync(&reason_hs).unwrap_or_else(|e| {
                tracing::warn!("passkey: RequestVerificationAsync failed: {:?}", e);
                return false.into(); // will not compile — handled below
            });
        match async_op.get() {
            Ok(UserConsentVerificationResult::Verified) => true,
            Ok(other) => {
                tracing::debug!("passkey: Windows Hello result: {:?}", other);
                false
            }
            Err(e) => {
                tracing::warn!("passkey: Windows Hello error: {:?}", e);
                false
            }
        }
    })
    .await
    .unwrap_or(false);

    Ok(result)
}

/// Called by the frontend to request local authentication before a sensitive
/// operation. Returns true if authenticated.
/// Returns false (never silently allows) if unavailable or denied.
/// Callers should check `cmd_biometric_available()` first to get the reason string.
pub async fn cmd_local_auth_impl(reason: String) -> bool {
    if !is_biometric_available() {
        let why = biometric_unavailable_reason();
        tracing::warn!(
            "passkey: auth unavailable ({:?}) — denying (not silently allowing)",
            why
        );
        return false;
    }
    match authenticate(&reason).await {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("passkey: auth API error: {} — denying", e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_available_returns_bool() {
        let _ = is_biometric_available();
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn linux_biometric_available() -> bool {
    std::path::Path::new("/usr/lib/fprintd").exists()
        || std::path::Path::new("/usr/libexec/fprintd").exists()
        || which_available("fprintd-verify")
        || which_available("zenity")
        || which_available("kdialog")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn linux_authenticate(reason: &str) -> anyhow::Result<bool> {
    if which_available("fprintd-verify") {
        let output = tokio::process::Command::new("fprintd-verify")
            .arg("-f")
            .arg("any")
            .output()
            .await;
        if let Ok(out) = output {
            return Ok(out.status.success());
        }
    }

    if which_available("zenity") {
        let reason_owned = reason.to_owned();
        let output = tokio::process::Command::new("zenity")
            .args([
                "--password",
                "--title",
                "Diatom — Authentication Required",
                "--text",
                &reason_owned,
            ])
            .output()
            .await;
        if let Ok(out) = output {
            return Ok(out.status.success() && !out.stdout.is_empty());
        }
    }

    if which_available("kdialog") {
        let output = tokio::process::Command::new("kdialog")
            .args(["--password", reason])
            .output()
            .await;
        if let Ok(out) = output {
            return Ok(out.status.success());
        }
    }

    anyhow::bail!(
        "passkey: no authentication mechanism available on this Linux system.          Install fprintd (biometric) or zenity/kdialog (password prompt)."
    )
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn which_available(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
