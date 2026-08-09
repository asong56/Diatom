# Diatom — Axioms

> This document is the axiomatic foundation of Diatom. It defines what Diatom
> is and what Diatom will never become. Every feature, every architectural
> decision, and every partnership proposal must pass review against these axioms.
> If a change conflicts with any axiom, the change is rejected — the axiom is
> never amended.
>
> "Axiom" is chosen deliberately. These are not philosophical preferences open
> to reinterpretation. They are load-bearing constraints; violating one collapses
> the integrity of the whole. The reasoning behind each axiom lives in README.md.

---

## Preamble — Affirmative Boundary

> Diatom is a tool for people to browse the open web without being tracked,
> analysed, or manipulated. Every feature must directly serve that goal, or
> directly serve the ability of developers using Diatom to understand the
> web they are building.
>
> This sentence is not a marketing tagline. It is an inclusion test. If a
> proposed feature cannot be justified by it, the feature does not enter
> the product — regardless of how well it passes the negative constraints below.

---

## I. Sovereignty Axioms

### Axiom 1 — No Centralised Sync Server
Diatom will never operate a server that stores user bookmarks, history, or any
browsing artefact. Peer-to-peer mesh sync is slow and requires both devices to
be online — that is an acceptable trade-off. A central server acquires a
god's-eye view of user behaviour; that is not.

**On Nostr relays:** Bookmark sync (opt-in) uses user-configured Nostr relays.
Relays are third-party servers, but they cannot form a god's-eye view because:
- All content is AES-256-GCM encrypted before leaving the device; relay
  operators see only ciphertext.
- Each sync session uses a freshly derived ephemeral keypair; consecutive
  sessions cannot be linked by relay operators.
- What relay operators **can** observe: connection timing, ciphertext size,
  ephemeral public key.
- What relay operators **cannot** observe: bookmark URLs, page titles, or any
  readable content.

Users may self-host a relay to eliminate even connection-timing exposure.
Noise_XX direct P2P (same-network sync) involves no third-party server at all
and is the preferred method when devices share a local network.

### Axiom 2 — Zen Mode Is a Commitment Gate
The 50-character unlock declaration is a ritual, not a speed bump. Making the
act of breaking focus conscious is the feature itself. A skip button destroys
its premise.

This axiom applies to the **default** configuration. Users who have genuinely
internalised the ritual may disable the gate via
`Settings → Focus → Require intent declaration` (`require_intent_gate: false`).
This is a deliberate opt-out, not a bypass. The gate remains enabled by default
for all new installations.

### Axiom 3 — Predictive Features Are Opt-In, Never Default
URL prefetch, search suggestions, predictive scrolling — each trades privacy for
milliseconds. The default posture is always the most conservative. Intent remains
completely private until the user explicitly acts.

---

## II. Legal Axioms

### Axiom 4 — No Official Platform-Specific Block-Rule Distribution
Diatom may publish its blocking engine as open source. The official repository
will never ship curated rule files targeting specific platforms by name.

### Axiom 5 — No DRM Circumvention
Widevine's absence is a deliberate boundary, not a technical limitation to
engineer around.

---

## III. Technical Axioms

### Axiom 6 — The Microkernel Stays Clean
No business logic enters the core. If a feature can be hot-swapped as a module,
it does not enter the kernel.

**Binary size ceilings (CI-enforced):**
- Tauri shell binary: **10 MB**
- `diatom-devpanel` (GPUI DevPanel): **40 MB**
- Combined RSS: **50 MB**

The browser chrome (tab bar, address bar, toolbar) is rendered by the system
WebView using bundled HTML and CSS, isolated from web content by Tauri's
WebView architecture. GPUI is used exclusively for the DevPanel.

### Axiom 7 — No Chromium
WebKit (WKWebView on macOS/iOS, WebKitGTK on Linux) is the system renderer.
WebView2 (Windows) is acceptable when WebKit is unavailable. Blink/Chromium
enters neither the build graph nor the runtime. Servo is the preferred long-term
direction when it reaches production readiness, but this is an aspiration, not
a binding constraint.

### Axiom 8 — Zero Telemetry
"Anonymous data" does not exist. Diatom's codebase calls no analytics service.
The integrated editor core strips all upstream telemetry crates at build time
(enforced by `scripts/strip-zed.sh`).

```
// These identifiers will never appear in the Diatom codebase:
// telemetry::event!(...)
// sentry::capture_message(...)
// reqwest::get("https://analytics.example.com/event")
```

### Axiom 9 — URL Stripping Is Rule-Based, Never AI-Delegated
Tracking-parameter removal is driven exclusively by curated regex and filter
lists (`src-tauri/src/engine/url_stripper.rs`). Delegating this decision to a
model introduces two failure modes: stripping a session ID that breaks login, or
missing a novel tracker hidden in an unusual parameter name. Static, audited
rules are the only acceptable mechanism.

### Axiom 10 — Fingerprinting Countermeasure Is Normalisation, Not Noise
Diatom normalises browser fingerprints to values statistically consistent with a
large population of common desktop hardware. It does not inject random noise.
Noise-based approaches produce detectable entropy signatures and can break site
functionality. Normalisation is invisible and deterministic.

---

## IV. Commercial Axioms

### Axiom 11 — No Default Search Engine Revenue Deals

### Axiom 12 — No Monetisation of User Attention

---

## V. Community Axioms

### Axiom 13 — Core Logic Stays Open Source

### Axiom 14 — No Module Registry Monopoly
Diatom accepts plugins from local paths, IPFS CIDs, and user-defined HTTP
sources. The Zed extension registry is treated as a read-only public index —
metadata is fetched without sending telemetry or account tokens.

**On sidecar extensions:** The sidecar mechanism is available only for
user-authored tools. Official Diatom features are not implemented as sidecars.
Diatom does not operate a sidecar registry, and does not provide distribution
infrastructure for third-party sidecars.

---

## VI. Editor Core Integration Axioms

### Axiom 15 — The Editor Core Is a Tool, Not a Product Dependency
Diatom integrates the Zed editor core for DevPanel functionality.
Any component of the editor core that touches cloud infrastructure — telemetry,
collaboration, cloud AI, remote execution, auto-update — is excluded at build
time. The exclusion mechanism may evolve; the principle does not.

### Axiom 16 — The AI Backend Is Always Local
All AI features served through the DevPanel use Diatom's local SLM
endpoint exclusively. No cloud AI dependency may enter the build graph,
regardless of how it is packaged or named.

The local SLM exposes an OpenAI-compatible HTTP API at `http://127.0.0.1:11435`
(endpoints: `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/completions`,
`GET /api/version`). External tools that support OpenAI-compatible backends —
VS Code extensions, Zed AI, Continue.dev — can point to this endpoint and use
the local model without any Diatom-specific integration. This is the only
supported external interface. The private `~/.diatom/resonance.sock` AI
protocol is deprecated; new integrations must use the standard HTTP API.

### Axiom 17 — Real-Time Collaboration Is Permanently Absent
Diatom is a single-user tool. Any feature enabling real-time shared editing,
voice or video calls, or broadcast channels is excluded.

### Axiom 18 — Editor Extensions Are Welcome; Editor Accounts Are Not
Any extension conforming to the editor's WASM extension API runs inside
Diatom's sandbox. No editor vendor account, cloud token, or hosted registry
authentication is required or requested.

### Axiom 19 — *(Retired)*
Formerly: upstream Zed editor-core upgrades use an explicit crate whitelist.
Retired along with `diatom_devtools`/`diatom_ui` (the GPUI-based DevPanel) —
there is no Zed source in this repository anymore, so there is nothing to
whitelist. See DEAD_CODE.md.

---

## VII. Data Sovereignty Axioms

### Axiom 20 — User Data Must Be Portable
Every category of data Diatom stores on behalf of the user must be exportable
in a standard, open format. Features that create data with no export path are
not permitted in stable releases. Retaining users by making their data
inescapable is prohibited; the only legitimate retention mechanism is being
genuinely useful.

| Data type        | Export format                                   |
|------------------|-------------------------------------------------|
| Museum archives  | Markdown (one `.md` file per bundle, with frontmatter) |
| Bookmarks        | Netscape Bookmark Format HTML                   |
| History          | CSV                                             |
| TOTP entries     | Aegis JSON (already implemented)                |
| RSS subscriptions| OPML                                            |
| Shadow Index     | JSON (URL, title, TF-IDF tags, timestamp)       |

### Axiom 21 — Plugin Ecosystem Boundary
Diatom does not operate a plugin registry and does not provide distribution
infrastructure for third-party extensions (see also Axiom 14). Official Diatom
features are not implemented as plugins, sidecars, or extensions. The boundary
between core and optional is defined by these axioms, not by packaging.

---

## Known Outbound Network Calls

All background network calls are documented here. None transmit user data
(browsing history, identifiers, credentials).

| Component | Endpoint | Purpose | Interval |
|---|---|---|---|
| Sentinel | `versionhistory.googleapis.com` | Chrome stable version (UA normalisation) | 1 hour |
| Sentinel | `developer.apple.com/news/releases/rss/…` | Safari version (macOS UA normalisation) | 1 hour |
| Sentinel | `chromereleases.googleblog.com/feeds/…` | CVE detection in current Chrome release | 1 hour |
| Blocker  | `easylist.to` (EasyList, EasyPrivacy, Fanboy) | Filter list refresh | Configurable (default: 24 h) |
| Blocker  | `raw.githubusercontent.com` (uBlock assets, Steven Black hosts) | Filter list refresh | Same cycle |
| Blocker  | `filters.adtidy.org` (AdGuard Base, Tracking Protection, Mobile Ads) | Filter list refresh | Same cycle |
| Blocker  | `pgl.yoyo.org` (Peter Lowe ad-server list) | Filter list refresh | Same cycle |
| Blocker  | `someonewhocares.org` (Dan Pollock hosts) | Filter list refresh | Same cycle |

All filter list requests use a generic Chrome UA — never the Diatom UA — so
third-party CDNs cannot fingerprint Diatom users from their update traffic.
| Breach   | `api.pwnedpasswords.com/range/<5-char prefix>` | k-anonymity password check (opt-in) | On user action |
| Breach   | `haveibeenpwned.com/api/v3/breachedaccount/<email>` | Email breach check (explicit opt-in; full email transmitted) | On user action |

Filter list update requests use a generic User-Agent, not the Diatom UA.
Breach password requests transmit only a 5-character SHA-1 prefix.
Breach email requests transmit the full email address; user must explicitly opt in.

---

## Permanent Black Zone

| Constraint | Rationale |
|---|---|
| Zen Mode intent gate (default on) | Ritual: removing the default removes the feature itself |
| Mesh P2P, no central server | Centralisation = god's-eye view = something that can be sold |
| WebUSB / WebMIDI disabled | The browser does not touch physical hardware |
| Fingerprint normalisation (not noise) | Deterministic, invisible, does not break site function |
| Service Worker force-suspended | Miss a push notification before allowing background tracking |
| 0-RTT and prefetch disabled (application layer) | Milliseconds are not worth trading for intent privacy. Note: system WebView engine behaviour is outside Diatom's control; this constraint applies to application-layer prefetch only |
| No skip buttons anywhere | Skip buttons are a betrayal of feature seriousness |
| Shell binary ≤ 10 MB | The browser shell stays lightweight |
| Combined RSS ≤ 50 MB | Physical constraint on a lightweight promise |
| Local AI only (no cloud fallback) | Cloud AI = your thoughts on someone else's server |
| URL stripping = regex rules only | AI-generated rules risk breaking login sessions |
| User data exportable in open formats | The only legitimate lock-in is quality |
