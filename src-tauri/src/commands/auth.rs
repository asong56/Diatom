use super::{St, es};

#[tauri::command]
pub async fn cmd_totp_list(state: St<'_>) -> Result<serde_json::Value, String> {
    let accounts = state.totp.lock().unwrap().list_accounts();
    Ok(serde_json::json!({ "accounts": accounts }))
}

#[tauri::command]
pub async fn cmd_totp_add(
    account: crate::auth::totp::TotpAccount,
    state: St<'_>,
) -> Result<String, String> {
    state.with_master_key(|key| {
        state
            .totp
            .lock()
            .unwrap()
            .add(account, &state.db, key)
            .map_err(es)
    })
}

#[tauri::command]
pub async fn cmd_totp_code(
    account_id: String,
    state: St<'_>,
) -> Result<crate::auth::totp::TotpCode, String> {
    state
        .totp
        .lock()
        .unwrap()
        .current_code(&account_id)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_totp_delete(account_id: String, state: St<'_>) -> Result<(), String> {
    state
        .totp
        .lock()
        .unwrap()
        .delete(&account_id, &state.db)
        .map_err(es)
}

#[tauri::command]
pub async fn cmd_totp_import(format: String, data: String, state: St<'_>) -> Result<u32, String> {
    state.with_master_key(|key| {
        state
            .totp
            .lock()
            .unwrap()
            .import(&format, &data, &state.db, key)
            .map_err(es)
    })
}

#[tauri::command]
pub async fn cmd_biometric_verify(reason: String) -> Result<bool, String> {
    crate::auth::passkey::verify(&reason).await.map_err(es)
}

#[tauri::command]
pub async fn cmd_trust_get(domain: String, state: St<'_>) -> Result<String, String> {
    Ok(state.trust.lock().unwrap().get(&domain).as_str().to_owned())
}

#[tauri::command]
pub async fn cmd_trust_set(domain: String, level: String, state: St<'_>) -> Result<(), String> {
    state
        .trust
        .lock()
        .unwrap()
        .set(&domain, &level, "user", &state.db);
    Ok(())
}

#[tauri::command]
pub async fn cmd_noise_fingerprint(state: St<'_>) -> Result<String, String> {
    let kp = state.with_master_key(|key| crate::sync::noise::derive_keypair_from_master(key));
    Ok(kp.fingerprint())
}
