# Diatom

**A minimalist, privacy-first, local-AI browser.**

[![Binary](https://img.shields.io/badge/binary-%E2%89%A410MB-green.svg)](#)
[![Status](https://img.shields.io/badge/status-v1.0.0-green.svg)](AXIOMS.md)

Most browsers are a window that lets you see the internet. Diatom is a filter that keeps the internet from seeing you.

It is not trying to replace Chrome. It is for people who have noticed that every scroll, every click, and every pause is being quietly recorded by dozens of third-party systems — and who have decided their attention is worth more than that.

---

## Why Diatom

The diatom is a single-celled alga that builds precise geometric shells from silica. In nature's smallest things, the most rigorous architecture. The name is a reminder: **restraint is a form of strength**.

Diatom runs entirely on your device. No accounts. No cloud sync. No analytics. No ads. No telemetry. Ever.

---

## Hard limits (enforced in code, not just policy)

| Constraint | Enforcement |
|---|---|
| Zero data upload, no exceptions | `AppState` has no outbound API endpoints |
| Zen Mode 50-character unlock ritual — never removable by default | `zen.js` character check has no bypass path |
| No centralised sync server, ever | Nostr relay sync is end-to-end encrypted; Noise_XX P2P involves no third-party server |
| Shell binary ≤ 10 MB | CI gate: build fails if exceeded |
| No Blink/Chromium bundled | Size budget enforcement: Blink ≈ 200 MB, budget = 10 MB |
| No WebExtensions compatibility layer | Features enter the kernel, not an extension store |
| WebUSB / WebMIDI permanently disabled | `sw.js` + `diatom-api.js`: physical boundary |

---

## Features

| Feature | Description |
|---|---|
| **Native ad blocking** | Aho-Corasick automaton — tracker requests are dropped before they reach the renderer. Ships a minimal built-in blocklist; subscribe to EasyList, EasyPrivacy, and others via `diatom://onboarding`. |
| **Fingerprint normalisation** | Canvas, WebGL, AudioContext, and navigator APIs normalised to the statistical mode of common desktop hardware. Deterministic — every Diatom instance presents the same surface, making individual identification impractical. |
| **Dynamic User-Agent (Sentinel)** | Polls Chrome and Safari version feeds hourly and synthesises a matching UA string. Diatom blends into the most common browser population rather than advertising itself. Polls use a generic Chrome UA so the poll traffic cannot fingerprint Diatom users. |
| **Museum (encrypted archive)** | AES-256-GCM encrypted page snapshots with tracker stripping, TF-IDF indexing, and FTS5 full-text search. Exportable as WARC or standard HTML archive. |
| **Museum sync** | Local-network sync via Noise_XX P2P (no third-party server). Cross-device async sync via user-chosen Nostr relay — relay sees only ciphertext. Both are opt-in. |
| **Native RSS** | Zero plugins. RSS 2.0 / Atom parser with folder organisation and reading mode. |
| **Built-in 2FA** | TOTP/HOTP engine that auto-detects 2FA forms and fills in the code. Exportable in Aegis JSON format. |
| **Vault** | AES-256-GCM encrypted credential store. Autofill for login forms. |
| **Local AI (Resonance)** | OpenAI-compatible API at `127.0.0.1:11435`. Curated models via Ollama: Qwen 2.5 3B, Phi-4 Mini, Gemma 3 4B. Also works with VS Code and Obsidian pointing to the same endpoint. |
| **DOM Crusher** | Ctrl+click any page element to permanently hide it. Rules persist per-domain. |
| **Zen Mode** | Blocks social and entertainment sites during focus sessions. Unlocking requires typing a 50-character intent declaration — a ritual, not a speed bump. Configurable site list. |
| **Vision Overlay** | Alt-drag any region → local Tesseract OCR → optional local translation. No network request. |
| **Peek preview** | Hovering a link for 600 ms shows a preview card. Previously-visited URLs resolve from the Museum cache with zero network requests. |
| **ToS Red-Flag Auditor** | Automatically extracts and analyses Terms of Service on registration pages. Flags AI training consent, data-sharing clauses, perpetual IP licences, and more. |
| **Breach monitor** | k-anonymity password check via HaveIBeenPwned (opt-in). Email breach check transmits the full address — explicit opt-in required. Results cached locally for 7 days. |
| **DOM Boosts** | Per-domain CSS and JS overrides. Applied after page load; never transmitted anywhere. |
| **Compatibility router** | Detects broken pages and hands off to the system browser with tracking parameters stripped. |
| **Wasm plugin sandbox** | Local-path plugins run inside a Wasm sandbox: 16 MB memory limit, 100 ms CPU budget per call, no filesystem or network access. |
| **Panic button** | Cmd/Ctrl+Shift+. hides all windows and replaces the active tab with a configurable decoy page. Optional full workspace wipe. |
| **War Report** | Running tally of tracker blocks, fingerprint noise injections, estimated RAM saved, and estimated time saved. Computed locally from the block log. |
| **Per-tab proxy** | Route individual tabs through a different proxy. Labs / Alpha. |
| **Adaptive tab budget** | Resource-aware tab sleeping. Sleep timer shortens as tab count approaches the configured limit. |

---

## Honest limitations

**Permanently out of scope:**
- Widevine L1/L3 on Linux — Google does not license the CDM to open-source projects. DRM streaming (4K Netflix, etc.) is handled by handing off to the system browser with tracking parameters stripped.
- Full iOS App Store distribution — Apple policy blocks custom Wasm kernels.
- WebExtensions API — incompatible with the binary size budget and security model.
- Bank U-Shield / NPAPI plugins — non-standard proprietary interfaces.

**Filter rules:** Diatom ships a minimal built-in blocklist. For broader coverage use the Privacy Presets button at `diatom://onboarding` to subscribe to EasyList, EasyPrivacy, URLhaus, and others. Diatom is the downloader; you choose the lists.

**System browser handoff** — `cmd_compat_handoff` strips tracking parameters before yielding:
- Legacy enterprise intranets with broken layout
- Banking pages requiring hardware token plugins
- DRM streaming

Privacy protection extends to the last moment before leaving Diatom.

---

## Getting started

### Prerequisites

```bash
# Rust stable
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Tauri CLI v2
cargo install tauri-cli --version "^2" --locked
```

### Platform dependencies

```bash
# macOS
xcode-select --install

# Linux (Ubuntu / Debian)
sudo apt install libwebkit2gtk-4.1-dev build-essential curl \
  libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libgpu-dev

# Windows
# Install WebView2 Runtime (built into Windows 11)
# https://developer.microsoft.com/microsoft-edge/webview2/
```

### First run

On first launch, Diatom opens the **Onboarding Wizard** (`diatom://onboarding`):
1. Checks for Ollama (local AI — optional)
2. Sets your privacy posture (Balanced / Strict / Minimal)
3. Subscribes to filter lists with one click
4. Shows active features

Re-open at any time via `diatom://onboarding`.

### Development

```bash
git clone https://github.com/asong56/Diatom.git
cd Diatom
cargo tauri dev
```

### Production build

```bash
cargo tauri build
# Output: ≤ 10 MB shell binary + separate diatom-devpanel binary
# macOS:   Diatom.app + .dmg
# Windows: Diatom.exe + .msi
# Linux:   diatom.deb + .AppImage
```

---

## Local AI setup (optional)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a curated model
ollama pull phi4-mini          # recommended — balanced speed and quality
ollama pull qwen2.5:3b         # faster, lower memory
ollama pull gemma3:4b          # longer context, multilingual
```

Once Ollama is running, Diatom auto-detects it at `127.0.0.1:11434`. No configuration needed.

**Address-bar shortcuts** (legacy slash-commands still work):

| Input | Behaviour |
|---|---|
| `/scholar <question>` | Research from your local Museum only |
| `/debug <issue>` | Page debug with console + network context |
| `/scribe <draft>` | Writing and editing |
| Natural language | Intent is detected automatically |

**Extreme Privacy Mode** (Labs) forces all inference into a Wasm sandbox — no filesystem access, no network, only in-memory page context. Inference is 5–20× slower and limited to short prompts.

---

## Project structure

```
Diatom/
├── src-tauri/              Tauri backend
│   └── src/
│       ├── engine/         Blocker, bandwidth limiter, net monitor,
│       │                   GhostPipe DoH, compat router, Wasm plugin sandbox
│       ├── privacy/        PrivacyConfig, fingerprint normalisation, OHTTP,
│       │                   onion mirror suggestions, threat list, Wi-Fi trust
│       ├── storage/        SQLite DB, Vault, Museum freeze/thaw (E-WBN),
│       │                   storage guard
│       ├── ai/             SLM server, AI download renamer, Shadow Index, MCP host
│       ├── browser/        Tab lifecycle, tab budget, per-tab proxy, DOM Crusher,
│       │                   DOM Boosts
│       ├── auth/           TOTP/2FA, platform passkeys, domain trust levels
│       ├── sync/           Nostr relay sync, Noise_XX P2P transport
│       └── features/       Zen, RSS, Panic button, Breach monitor, Search engines,
│                           ToS auditor, Sentinel, War Report, Labs, Compliance registry
│
├── src/                    Browser frontend (JS, CSS, UI pages)
│   ├── main.js             Boot sequence
│   ├── sw.js               Service worker — request interception, Zen enforcement
│   ├── index.html          Browser chrome
│   ├── browser/            Core browser modules (IPC, tabs, hotkey, IME fix, …)
│   ├── features/           Feature panels (Zen, DOM Crusher, ToS auditor, …)
│   ├── workers/
│   │   └── core.worker.js  TF-IDF, OPFS, idle indexing
│   └── ui/
│       ├── vault.html      diatom://vault
│       ├── onboarding.html diatom://onboarding
│       ├── home-base.html  diatom://home (new-tab page, Labs)
│       ├── labs.html       diatom://labs
│       └── about.html      diatom://about
│
├── shell/                  GPUI sidecar workspace
│   └── crates/
│       ├── diatom_bridge/  Local-SLM streaming chat client used by diatom_agent
│       └── diatom_agent/   Browser automation agent (planner, executor, tools)
│
├── scripts/
│   ├── strip-zed.sh        Strips Zed telemetry/collab crates before each build
│   └── check-black-zone.sh Verifies no banned identifiers entered the codebase
│
├── AXIOMS.md               Inviolable constraints — read before opening a PR
└── LICENSE                 BUSL-1.1, Change Date 2028, Change License MIT
```

---

## Known outbound network calls

All background network calls are documented here. None transmit user data (browsing history, identifiers, credentials).

| Component | Endpoint | Purpose | Interval |
|---|---|---|---|
| Sentinel | `versionhistory.googleapis.com` | Chrome stable version (UA normalisation) | 1 hour |
| Sentinel | `developer.apple.com/news/releases/rss/…` | Safari version (macOS UA normalisation) | 1 hour |
| Sentinel | `chromereleases.googleblog.com/feeds/…` | CVE detection in current Chrome release | 1 hour |
| Blocker | `easylist.to`, `filters.adtidy.org`, `raw.githubusercontent.com`, `pgl.yoyo.org`, `someonewhocares.org` | Filter list refresh | Configurable (default: 24 h) |
| Breach | `api.pwnedpasswords.com/range/<5-char prefix>` | k-anonymity password check (opt-in) | On user action |
| Breach | `haveibeenpwned.com/api/v3/breachedaccount/<email>` | Email breach check (explicit opt-in; full email transmitted) | On user action |

All Sentinel and filter list requests use a generic Chrome UA — never the Diatom UA.

---

## Philosophy

> *"A tool with boundaries is more trustworthy than a tool that is everywhere."*

**On centralisation:** Once a server stores your history, it acquires a god's-eye view. That view can be subpoenaed, sold, or leaked. The only safe central server is one that never exists.

**On convenience trade-offs:** URL prefetch, search suggestions, predictive scrolling — these trade privacy for milliseconds. Diatom defaults to the most conservative posture. Users may opt in; they never opt out of something they never agreed to.

**On fingerprint defence:** Random noise is detectable as noise. Normalisation to the statistical mode of common hardware is invisible — millions of real devices return the same values. Determinism is the stronger defence.

**On local AI:** Cloud AI means your thoughts live on someone else's server. Diatom's AI is local-only, not as a feature limitation but as a privacy guarantee with no asterisk.

**On DRM:** Widevine's absence is a deliberate boundary, not a technical problem to route around.

**On attention:** Diatom's goal is to return your attention to you — not to repackage it differently.

---

## Contributing

Read [AXIOMS.md](AXIOMS.md) before opening a PR. Every change must pass the axioms — the CI will catch most violations automatically.

Bug reports and feature requests: [github.com/asong56/Diatom/issues](https://github.com/asong56/Diatom/issues)
