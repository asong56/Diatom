# RULE.md — Diatom project-specific instructions

Distilled from `AXIOMS.md`, `.github/CONTRIBUTING.md`, and `.github/workflows/ci.yml`.
Read `AXIOMS.md` for the full text and rationale — this file is a quick
reference, not a replacement.

## Non-negotiable (will fail CI or violate an axiom)

- **No Chromium.** WebKit/WebView2 only. Never add a Blink/CEF dependency.
- **Zero telemetry.** No analytics/telemetry/tracking calls of any kind, ever.
  CI greps `src-tauri/src/` for `diatom.io|api.diatom|telemetry.diatom` and
  fails the build if any match.
- **Shell binary ≤ 10 MB.** CI-enforced. Think twice before adding a heavy
  dependency to `src-tauri`.
- **DNS-over-HTTPS is mandatory for Diatom's own outbound requests**, with no
  toggle to disable it — only which resolver to use. ECH on by default where
  the destination supports it. This scope is Diatom's own requests only, not
  page loads inside the embedded WebView (Diatom doesn't own that network
  stack — Axiom 10).
- **URL tracking-parameter stripping is rule-based only** — never delegate it
  to a model (Axiom 8).
- **Fingerprinting countermeasure is normalisation, not noise** (Axiom 9).
- Any new persisted data type needs a documented open-format export path
  (Axiom 20) before it ships stable, plus a row in `AXIOMS.md §VII`.
- `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test
  --all-features` must all pass (CI gate).

## Process rules

- **Labs lifecycle**: new experimental features enter through
  `src/ui/labs.html` + `src-tauri/src/features/labs.rs`, default OFF. Max two
  stable minor releases in Labs, then graduate (full review + axiom check +
  docs) or get removed. "Permanent Lab" is not a valid end state.
- **`diatom://` URLs are internal-only.** Never write `diatom://labs` etc. in
  user-facing docs — say "open the Labs page" instead.
- **Official features never go through the sidecar/plugin mechanism.** That
  path is for user-authored tools only (Axiom 21 boundary).
- **New Resonance/AI capabilities are MCP tool definitions**, not new
  slash-command syntax (no new `/scholar`-style commands).
- **Zed vendor pin**: quarterly bump schedule only (unless a security fix
  forces it), must pass `scripts/check-zed-deps.sh`, new crates need a
  justification comment in `scripts/known-zed-crates.txt`.
- **`EvalJs` bridge / `HandshakeMessage` handshake**: **removed as of this
  pass.** It was confirmed dormant (see git history / CHANGES for the
  removal commit) — `dev_panel.rs`, and the DevPanel-only modules of
  `diatom_bridge` (`client`/`server`/`zed_link`/`transport`/`protocol`) are
  gone. `diatom_bridge` now contains only `slm_adapter` (the local-SLM chat
  client `diatom_agent` actually uses). If this ever needs to come back,
  don't just re-add the files — first decide whether it's actually going to
  be wired into a registered command this time, or it'll rot the same way
  again.
- Security vulnerabilities go through GitHub Security Advisories, not public
  issues.

## House conventions (not CI-enforced, but consistent in the existing code)

- Reuse `/browser/ipc.js` for `invoke`/`listen`/`emit` in any new frontend
  page. It already implements the correct "reject cleanly when
  `window.__TAURI__` is absent" fallback — don't redefine `invoke` locally
  per page (two existing pages did, and one of the two redefinitions
  silently swallows the failure instead of rejecting — see REVIEW.md for the
  concrete breakage this causes).
- `commands/*.rs` handlers stay thin; real logic lives in the subsystem
  module (`browser/`, `storage/`, `engine/`, etc.).
- `.lock().unwrap()` / `.read().unwrap()` / `.write().unwrap()` on
  poisoned-lock is the accepted idiom in this codebase — not itself a defect
  to "fix" wholesale.
- Comments explain *why* (trade-offs, non-obvious constraints), matching
  Lazy.md's convention — the existing Rust code already does this well
  (e.g. `engine/ech.rs`).

## Known gaps (verified against the actual repo contents, not assumed)

- No frontend lint/build/test tooling at all — no `package.json`, no test
  runner for the ~13k lines of JS/HTML/CSS.
- IPC command handlers (`commands/*.rs`) and `state.rs` have no direct unit
  tests — the 164 inline `#[test]`s cover the subsystem modules underneath,
  not the command layer itself.
- `diatom-devpanel` / DevPanel is gone from the *compiled app*: `dev_panel.rs`
  deleted, `diatom_bridge` trimmed to just `slm_adapter`. What's still on
  disk but permanently unbuildable in this repo: `shell/crates/diatom_devtools`
  and `shell/crates/diatom_ui` — both already excluded from
  `shell/Cargo.toml`'s `[workspace] members`, and both depend on
  `gpui = { path = "../gpui" }`, which doesn't exist anywhere in this repo
  (no `zed-vendor/`, no `shell/crates/gpui`). They cannot compile here even
  if re-added to `members`. The Zed-vendor tracking scripts
  (`scripts/strip-zed.sh`, `check-zed-deps.sh`, `check-black-zone.sh`) and
  Axiom 19 exist solely to police that now-unbuildable target — see
  DEAD_CODE.md for the full list of what's still sitting around unused and
  needs an explicit decision, not just DevPanel.

*(If this file already exists when you next update it: preserve everything
above and only add newly-detected conventions — don't remove documented
rules just because you didn't personally verify them this pass.)*
