'use strict';

// Tauri v2's global-injection API is namespaced (window.__TAURI__.core.invoke),
// matching the `@tauri-apps/api/core` module shape — not the flat
// window.__TAURI__.invoke from v1. `listen`/`emit` below already used the
// correct namespaced form (window.__TAURI__.event.*); this line hadn't been
// updated to match, so it silently fell through to the "unavailable" stub
// even when window.__TAURI__ was genuinely present.
const invoke = window.__TAURI__?.core?.invoke
    ?? (() => Promise.reject(new Error('Tauri IPC not available')));

export { invoke, listen };

function listen(event, handler) {
    return window.__TAURI__?.event?.listen(event, handler)
        ?? Promise.resolve(() => {});
}

export function emit(event, payload) {
    return window.__TAURI__?.event?.emit(event, payload);
}

// ── Tab management ────────────────────────────────────────────────────────────
export const tabCreate          = (url)                        => invoke('cmd_tab_create',            { url });
export const tabClose           = (tabId)                      => invoke('cmd_tab_close',             { tabId });
export const tabActivate        = (tabId)                      => invoke('cmd_tab_activate',          { tabId });
export const tabUpdate          = (tabId, url, title, dwellMs) => invoke('cmd_tab_update',            { tabId, url, title, dwellMs });
export const tabSleep           = (tabId, deep, snapshot)      => invoke('cmd_tab_sleep',             { tabId, deep, snapshot });
export const tabWake            = (tabId)                      => invoke('cmd_tab_wake',              { tabId });
export const tabsState          = ()                           => invoke('cmd_tabs_state');
export const tabBudgetConfigSet = (cfg)                        => invoke('cmd_tab_budget_config_set', cfg);
export const tabScreenshot      = ()                           => invoke('cmd_tab_screenshot');

// ── History ───────────────────────────────────────────────────────────────────
export const historySearch = (query, limit) => invoke('cmd_history_search', { query, limit });
export const historyClear  = ()             => invoke('cmd_history_clear');

// ── Bookmarks ─────────────────────────────────────────────────────────────────
export const bookmarkAdd    = (url, title, tags, ephemeral) => invoke('cmd_bookmark_add',    { url, title, tags, ephemeral });
export const bookmarkList   = ()                            => invoke('cmd_bookmark_list');
export const bookmarkRemove = (id)                          => invoke('cmd_bookmark_remove', { id });

// ── Settings (generic key/value store) ───────────────────────────────────────
export const settingGet = (key)        => invoke('cmd_setting_get', { key });
export const settingSet = (key, value) => invoke('cmd_setting_set', { key, value });

// ── Museum (page archive) ─────────────────────────────────────────────────────
export const freezePage   = (payload) => invoke('cmd_freeze_page',   { payload });
export const museumList   = (limit)   => invoke('cmd_museum_list',   { limit });
export const museumSearch = (query)   => invoke('cmd_museum_search', { query });
export const museumDelete = (id)      => invoke('cmd_museum_delete', { id });
export const museumThaw   = (id)      => invoke('cmd_museum_thaw',   { id });

// ── DOM Crusher ───────────────────────────────────────────────────────────────
export const domCrush       = (domain, selector) => invoke('cmd_dom_crush',        { domain, selector });
export const domBlocksFor   = (domain)           => invoke('cmd_dom_blocks_for',   { domain });
export const domBlockRemove = (id)               => invoke('cmd_dom_block_remove', { id });


// ── Privacy / threat detection ────────────────────────────────────────────────
export const privacyConfigGet = ()       => invoke('cmd_privacy_config_get');
export const privacyConfigSet = (config) => invoke('cmd_privacy_config_set', { config });
export const threatCheck      = (domain) => invoke('cmd_threat_check',        { domain });
export const threatRefresh    = ()       => invoke('cmd_threat_list_refresh');


// ── TOTP / 2FA ────────────────────────────────────────────────────────────────
export const totpList   = ()                                 => invoke('cmd_totp_list');
export const totpAdd    = (issuer, account, secret, domains) => invoke('cmd_totp_add',    { issuer, account, secret, domains });
export const totpCode   = (entryId)                          => invoke('cmd_totp_code',   { entryId });
export const totpDelete = (entryId)                          => invoke('cmd_totp_delete', { entryId });

// ── Trust ─────────────────────────────────────────────────────────────────────
export const trustGet = (domain)        => invoke('cmd_trust_get', { domain });
export const trustSet = (domain, level) => invoke('cmd_trust_set', { domain, level });

// ── Local AI (SLM) ────────────────────────────────────────────────────────────
export const slmStatus       = ()        => invoke('cmd_slm_status');
export const slmComplete     = (payload) => invoke('cmd_slm_complete',      { payload });
export const slmReset        = ()        => invoke('cmd_slm_reset');
export const slmSetModel     = (modelId) => invoke('cmd_slm_set_model',     { modelId });
export const slmServerToggle = (enable)  => invoke('cmd_slm_server_toggle', { enable });
export const shadowSearch    = (query)   => invoke('cmd_shadow_search',     { query });
export const mcpStatus       = ()        => invoke('cmd_mcp_status');

// ── Labs ──────────────────────────────────────────────────────────────────────
export const labsList = ()            => invoke('cmd_labs_list');
export const labSet   = (id, enabled) => invoke('cmd_lab_set', { id, enabled });

// ── System ────────────────────────────────────────────────────────────────────
export const homeBaseData      = ()    => invoke('cmd_home_base_data');
export const peekFetch         = (url) => invoke('cmd_peek_fetch',        { url });
export const powerBudgetStatus = ()    => invoke('cmd_power_budget_status');
export const signalWindowReady = ()    => invoke('cmd_signal_window_ready');
export const complianceRegistry = ()   => invoke('cmd_compliance_registry');

// ── Vault ──────────────────────────────────────────────────────────────────────
export const vaultList     = ()       => invoke('cmd_vault_list');
export const vaultAdd      = (entry)  => invoke('cmd_vault_add',      { entry });
export const vaultUpdate   = (entry)  => invoke('cmd_vault_update',   { entry });
export const vaultDelete   = (id)     => invoke('cmd_vault_delete',   { id });
export const vaultAutofill = (domain) => invoke('cmd_vault_autofill', { domain });


// ── Boosts ────────────────────────────────────────────────────────────────────
export const boostsForDomain = (domain) => invoke('cmd_boosts_for_domain', { domain });
export const boostsList      = ()       => invoke('cmd_boosts_list');
export const boostUpsert     = (rule)   => invoke('cmd_boost_upsert', { rule });
export const boostDelete     = (id)     => invoke('cmd_boost_delete', { id });

// ── Batched invocation ────────────────────────────────────────────────────────
// Coalesces multiple IPC calls within the same animation frame.
// Only the last call per command name is retained.
const _batchQueue = new Map();
let   _batchRaf   = null;

export function batchInvoke(command, args) {
    return new Promise((resolve, reject) => {
        _batchQueue.set(command, { args, resolve, reject });
        if (!_batchRaf) {
            _batchRaf = requestAnimationFrame(async () => {
                _batchRaf = null;
                const pending = [..._batchQueue.entries()];
                _batchQueue.clear();
                for (const [cmd, { args: a, resolve: res, reject: rej }] of pending) {
                    try { res(await invoke(cmd, a)); } catch (e) { rej(e); }
                }
            });
        }
    });
}
