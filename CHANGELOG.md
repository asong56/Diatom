## v0.9.2 — The Repair

**Theme:** Fix every structural gap between what Diatom claims to do and what it actually does.

---

### 🔴 Critical Security Fixes

- **[FIX-03] SSRF prevention in `cmd_fetch`** — Requests to private/loopback addresses (`127.x`, `10.x`, `192.168.x`, `169.254.x`, `file://`) are now blocked at the IPC layer. Previously any page JS could use `cmd_fetch` to reach the local SLM server or LAN router admin panels.

- **[FIX-04] DNS query ID randomised** — `threat.rs` hardcoded `0xDEAD` as the DNS transaction ID, making Quad9 responses trivially forgeable. Now uses `rand::random::<[u8;2]>()` per query.

- **[FIX-06] `cmd_setting_set` write whitelist** — Page JS can no longer overwrite `master_key_hex`, `sentinel_cache`, `consent:*`, or `lab_*` keys via the IPC command. A strict allowlist of safe keys is enforced.

- **[FIX-SLM-CSRF] SLM API restricted to localhost origins** — `:11435` now validates the `Origin` header and rejects any request from a non-localhost origin, preventing cross-site access to the local AI server.

- **[FIX-05-totp] TOTP `match_domain()` prefix attack closed** — `"evilexample.com".ends_with("example.com")` returned `true`. Now requires an exact match or a leading-dot subdomain (`.example.com`).

---

### 🔴 Data Loss Fixes (Persistence)

- **[FIX-persistence-totp] TotpStore is now DB-backed** — 2FA entries are encrypted with the app master key (AES-256-GCM) and persisted to a new `totp_entries` table (Migration v3). Previously all entries were lost on restart.

- **[FIX-persistence-trust] TrustStore is now DB-backed** — L0–L3 per-domain trust levels are written to `trust_profiles` table on every change. Previously reset to Standard on every restart.

- **[FIX-persistence-rss] RssStore is now DB-backed** — Feeds and items sync to the existing `rss_feeds`/`rss_items` tables (Migration v1). Previously the tables were created but never read or written by the store.

- **[FIX-zen] Zen Mode state persists across restarts** — `cmd_zen_activate/deactivate/set_aphorism` now call `zen_save()` after every state change. On startup `AppState::new()` loads from `zen_state` table (Migration v3).

- **[FIX-17] `fire_workspace()` full cleanup** — Now atomically deletes: history, bookmarks, Museum bundles (with physical `.ewbn` file removal), and the workspace row itself. Previously only history was cleared.

---

### 🔴 Core Feature Activation (Previously Dead Code)

- **[FIX-__DIATOM_INIT__] Fingerprint noise seed chain repaired** — `main.rs` now injects `window.__DIATOM_INIT__` with the workspace `noise_seed`, `crusher_rules`, and `zen_active` flag *before* `diatom-api.js` is evaluated. Previously `__DIATOM_INIT__` was never set, so the xorshift32 PRNG always fell back to `Math.random()` and workspace seed rotation had no effect.

- **[FIX-privacy.rs] `PrivacyConfig::injection_script()` now runs** — `setup()` now calls `st.privacy.read().unwrap().injection_script()` and evals the result. The module was fully implemented but had zero call sites.

- **[FIX-14] `current_ua()` now uses Sentinel cache** — `state.rs::current_ua()` was a stub that ignored its parameter and always returned `DIATOM_UA`. It now calls `blocker::dynamic_ua()` when the Sentinel cache is fresh.

- **[FIX-14b] `sentinel_ua` lab registered** — `labs.rs::all_labs()` now includes `sentinel_ua` so users can find and enable it. The lab was referenced in `main.rs` and `blocker.rs` but missing from the catalogue.

- **[FIX-07-urlhaus] URLhaus refresh decoupled from Quad9** — The weekly threat list refresh loop no longer gates on `quad9_enabled`. URLhaus is a local offline list; disabling Quad9 DoH should not prevent it from staying fresh.

- **[FIX-sentinel] Sentinel always spawned** — The background task now runs unconditionally. The lab gate only controls whether the synthesised UA is *applied*; CVE awareness requires the version data regardless.

---

### 🟠 Security Hardening

- **[FIX-25] Chrome UA uses full version number** — `sentinel.rs::chrome_ua_windows()` now produces `Chrome/124.0.6367.207` instead of the detectable `Chrome/124.0.0.0` form.

- **[FIX-09-webgl] WebGL renderer/vendor strings platform-branched** — Windows users no longer receive `"Apple M-series"` as their WebGL renderer. Strings now match the actual OS in `__DIATOM_INIT__.platform`.

- **[FIX-10-langs] `navigator.languages` no longer hardcoded to Chinese** — The previous `['zh-CN','zh','en-US','en']` fingerprinted every user identically. Now uses `['en-US','en']` as a privacy-preserving default. Future versions will read the OS locale.

- **[FIX-12-canvas] `toDataURL()` now intercepted** — `diatom-api.js` previously only patched `getImageData()`. FingerprintJS and similar tools primarily use `toDataURL()`. Both paths now route through the seeded PRNG noise layer.

- **[FIX-08-noise] `cmd_noise_seed` no longer returns raw seed** — Returns an opaque timestamp instead. Previously page JS could read the seed and reconstruct the full PRNG state to cancel noise.

- **[FIX-decoy-globals] Decoy caches moved into `AppState`** — `ROBOTS_CACHE` and `RATE_LIMITER` were process-level globals, bypassing workspace isolation. Both are now fields of `DecoyState` inside `AppState`, reset on workspace switch.

- **[FIX-decoy-log] `get_decoy_log()` now returns real data** — Previously always returned `vec![]`. Now reads `decoy_log_*` keys from the meta table that `fire_after_check()` writes after each successful request.

- **[FIX-13-compat] Compat banner button now works** — `compat_hint_banner()` called `window.__diatom_compat_handoff()` which was undefined. `diatom-api.js` now defines this function, routing to `cmd_compat_handoff` via the Tauri IPC bridge.

- **[FIX-12-compat] `dom_mutation_storm` wired into `appears_broken()`** — The signal was collected but silently ignored in the broken-page heuristic. Now contributes to compatibility detection.

---

### 🟠 Data Integrity Fixes

- **[FIX-15] `content_hash` now hashes content** — Was hashing the URL string (`blake3::hash(url.as_bytes())`). Now hashes the stripped HTML content, enabling true content-based deduplication and preventing orphan `.ewbn` files.

- **[FIX-16] `museum_fts` kept in sync via triggers** — Migration v2 now creates `AFTER INSERT/DELETE/UPDATE` triggers on `museum_bundles` so the FTS5 virtual table never returns stale results for deleted bundles.

- **[FIX-19] `insert_reading_event()` is now atomic** — Two separate lock acquisitions replaced with a single `BEGIN IMMEDIATE … COMMIT` transaction, preventing race conditions in the ring-buffer eviction.

- **[FIX-20] Museum delete/thaw use direct ID lookup** — `cmd_museum_delete` and `cmd_museum_thaw` previously scanned a capped list of 999 bundles. Now use `get_bundle_by_id()` — a direct primary-key lookup with no cap.

- **[FIX-18] `search_history()` escapes LIKE wildcards** — `%` and `_` in user queries are now properly escaped with `ESCAPE '\\'` so searches for `50%` or `test_page` don't produce wildcard results.

- **[FIX-26] RSS guid-index rebuilt after ring-buffer eviction** — Evicted items were removed from the in-memory `Vec` but their guids were also removed from `guid_index`, causing them to be re-fetched as "new" on the next sync. Index is now rebuilt from surviving items only.

---

### 🟡 Code Quality / Architecture

- **[FIX-05] Migration v2 `ALTER TABLE` is now idempotent** — Statements are run per-statement with duplicate-column errors silently ignored, preventing startup crashes on partially-migrated databases.

- **[FIX-07-echo] `cmd_echo_compute` now checks consent** — `compliance.rs` marked `echo_analysis` as `requires_consent: true` but `cmd_echo_compute` never checked. Now consistent with `cmd_decoy_fire`.

- **[FIX-11-warreport] War Report `time_saved_min` now real data** — `cmd_preprocess_url` calls `db.add_time_saved()` on every blocked request (0.9 s heuristic). The column is no longer permanently zero.

- **[FIX-27] `upgrade_https()` case-insensitive** — `HTTP://example.com` and `Http://` now correctly upgrade to HTTPS.

- **[FIX-29] Removed `"stats."` and `"metrics."` from built-in blocklist** — Too broad: `stats.gov`, `metrics.company.com`, `statistics.wikipedia.org` were being blocked. Removed.

- **[FIX-30] `oldest_bundle_iso` uses `YYYY-MM-DD` date format** — Was using ISO week format (`2025-W42`). Now human-readable.

- **[FIX-31] Removed Google Scholar and Reddit from noise domains** — Scholar returns CAPTCHA; Reddit's `robots.txt` prohibits automated access. Both removed from the decoy target list.

- **[FIX-decoy-deadlock] `cmd_decoy_fire` async deadlock fixed** — The previous implementation held a `std::sync::MutexGuard` across `.await` points. Refactored into synchronous `pre_check()` + async `fire_after_check()` to comply with Rust's `Send` requirement for async tasks.

- **[FIX-25-ua] Chrome UA full version** — `sentinel.rs` now emits `Chrome/124.0.6367.207` (full 4-part version from API), not `Chrome/124.0.0.0`.

---

### ✨ New Features

- **[NEW] `cmd_init_bundle` IPC command** — Returns the `DiatomInitBundle` payload (noise_seed, crusher_rules, zen_active, platform) for the frontend to inject as `window.__DIATOM_INIT__` on each navigation.

- **[NEW] Onboarding wizard** (`src/ui/onboarding.html`) — 5-step first-run setup: Welcome → Ollama detection → Privacy posture selection → Filter subscription → Done. Replaces the `curl` install barrier with a GUI flow.

- **[NEW] Privacy Presets / Filter Subscriptions** — `cmd_filter_sub_add`, `cmd_filter_subs_list`, `cmd_filter_sub_sync`. Users can subscribe to EasyList, EasyPrivacy, or URLhaus with one click. Diatom downloads; the user controls which lists.

- **[NEW] Nostr relay management** — `cmd_nostr_relay_add`, `cmd_nostr_relays`. Foundation for encrypted async P2P sync (Museum bundles, bookmarks) without requiring both devices online simultaneously.

- **[NEW] Onboarding DB tracking** — `cmd_onboarding_complete`, `cmd_onboarding_is_done`, `cmd_onboarding_all`. Tracks first-run wizard completion per step.

- **[NEW] Migration v3** — Adds tables: `totp_entries`, `trust_profiles`, `filter_subscriptions`, `nostr_relays`, `onboarding`, `zen_state`.

---

### Database Schema Changes

| Version | Change |
|---|---|
| v3 | `totp_entries` — encrypted TOTP secrets |
| v3 | `trust_profiles` — per-domain trust levels |
| v3 | `filter_subscriptions` — Privacy Presets |
| v3 | `nostr_relays` — P2P sync relay URLs |
| v3 | `onboarding` — first-run wizard steps |
| v3 | `zen_state` — persistent Zen Mode config |
| v2 | FTS5 triggers for `museum_bundles` sync |
| v2 | `format` column now accepts `'filterlist'` |
# Diatom — Development Log

A vibe-coded browser built from first principles, one version at a time.

---

## v0.9.0 — The Scheduler (current)

**Theme:** From information consumer to compute orchestrator.

- **Local AI Microkernel** (`slm.rs`): OpenAI-compatible API at `127.0.0.1:11435`. Three curated models: Qwen 2.5 3B (fast), Phi-4 Mini (balanced), Gemma 3 4B (deep context). Auto-detects Ollama/llama.cpp; falls back to Candle Wasm. Other local apps can use Diatom as their AI backend.
- **Extreme Privacy AI Mode**: When active, all inference is sandboxed to Candle Wasm — no filesystem access, no network, only in-memory page content.
- **Adaptive Tab Budget** (`tab_budget.rs`): Three interlocking models. Resource-Aware Scaling: T_max = ⌊M_available × ρ / ω_avg⌋. Golden Ratio Zones: Focus (61.8%) / Buffer (38.2%). Screen Gravity: 3 tabs on phone, 8 on laptop, 10 on desktop, 13 on ultrawide. Entropy-reduction sleep timer shortens as pressure rises.
- **`diatom://labs`** (`labs.rs` + `src/ui/labs.html`): 14 experimental features — AI, performance, privacy, sync, interface. Instrument-quality UI: Instrument Serif + DM Mono, paper-and-ink palette, per-card risk assessment.
- **P0 compile fixes**: Added 6 previously-missing modules — `blocker.rs`, `tabs.rs`, `privacy.rs`, `totp.rs`, `trust.rs`, `rss.rs`.
- **Browser chrome**: `index.html`, `diatom.css` — precision UI with zen mode slide, AI panel, budget indicator.
- License changed from MIT to **BUSL-1.1** (3-year protection, Change License → MIT).

---

## v0.8.0 — Bug Eradicator

**Theme:** Fix every fatal defect inherited from the research branch.

- Fixed `commands.rs` stray token `(§7.1 mitigation)` that prevented compilation.
- Fixed `decoy.rs` `block_on` deadlock inside Tokio runtime.
- Fixed `db.rs` `settings` → `meta` table rename migration for v7.0 data preservation.
- Ported `crdt.rs` from v8 research: OR-Set + LWW-Register Museum sync, BLAKE3 chunk integrity, temporal jitter injection.
- Rewrote `zkp.rs`: replaced integer M127 arithmetic (no ZK properties) with Ristretto255 Schnorr Sigma proofs — verify function now actually verifies.
- Hardened `ohttp.rs`: honest compliance documentation, fire-and-forget semantics clearly labelled, response decapsulation marked TODO.
- Ported `pqc.rs` from v8 with conditional compilation guard (`--features pqc`).
- Added `PHILOSOPHY.md` (12 prohibitions + permanent black zone table).

---

## v0.7.0 — Frontier Tech

**Theme:** Ship the most advanced privacy and sync primitives in any open-source browser.

- The Echo: weekly personality spectrum (Scholar / Builder / Leisure) from reading behaviour.
- E-WBN Freeze: AES-256-GCM encrypted offline page archives (Museum).
- War Report: narrative anti-tracking statistics.
- CRDT Museum Sync (research): OR-Set conflict-free merge for offline devices.
- Post-quantum cryptography stub (research): Kyber-768 + Dilithium-3.
- Oblivious HTTP relay integration (research).
- Zero-knowledge proof identity protocol (research).

---

## v0.6.0 — Architecture & Philosophy

**Theme:** Code modularisation and product ethics locked in writing.

- Unified `AppState` — eliminated N independent `Arc<Mutex<_>>` locks.
- Single `unix_now()`, `new_id()`, `domain_of()` — removed 5 duplicate copies each.
- `compliance.rs`: consent gating for legally complex features.
- `storage_guard.rs`: LRU eviction with configurable budget.
- `a11y.rs`: ARIA injection and keyboard navigation.
- `compat.rs`: legacy site detection with tracking-clean system browser handoff.
- Product philosophy drafted: "A tool with boundaries is more trustworthy than a tool that is everywhere."

---

## v0.5.0 — Offline & UI

**Theme:** The browser works when the internet doesn't.

- Museum v1: snapshot-based offline reading.
- Service Worker with offline fallback strategy.
- Reading mode with typographic optimisation.
- Zen mode with 50-character unlock ritual.
- DOM Crusher: CSS selector–based element removal.

---

## v0.4.0 — Mesh Networking

**Theme:** Devices talk to each other without a server.

- Mesh P2P: WebRTC-based local network tab syncing.
- Dead Man's Switch: time-gated workspace self-destruct.
- RSS reader with workspace isolation.
- Threat intelligence via Quad9 DoH.

---

## v0.3.0 — Workspaces & Identity

**Theme:** The browser knows who you are in each context.

- Workspace isolation: cookies, history, and storage partitioned per workspace.
- Reading mode: Readability algorithm, configurable typography.
- Trust levels: per-domain capability grants (L0–L3).
- TOTP/HOTP 2FA manager built into the chrome.

---

## v0.2.0 — Speed & Privacy

**Theme:** Faster pages through less data.

- Aho-Corasick tracker blocker with O(n) matching.
- LZ4 ZRAM tab compression (80 MB → ~20 MB per deep-sleep tab).
- Shallow + Deep sleep tab lifecycle.
- UTM/fbclid/gclid parameter stripping.
- HTTPS upgrade for all non-localhost origins.

---

## v0.1.0 — The Spark

**Theme:** An extremely private browser that uses less RAM.

- Tauri shell with a single WebView.
- SQLite history with workspace partitioning.
- Basic tab management with LRU sleep candidates.
- Fingerprint noise injection (Canvas, WebRTC, Battery, USB).
- "Why does my browser need 4 GB of RAM?" — the question that started this.
