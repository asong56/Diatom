# Diatom

**A minimalist, privacy-first, local-AI browser.**

[![Binary](https://img.shields.io/badge/binary-%E2%89%A410MB-green.svg)](#)
[![Status](https://img.shields.io/badge/status-v0.14.3-yellow.svg)](AXIOMS.md)

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
| Zen Mode 50-character unlock ritual — never removable | `zen.js` character check has no bypass path |
| No centralised sync server, ever | Architecture constraint: Mesh uses mDNS/BLE only |
| Binary size ≤ 10 MB | CI gate: build fails if exceeded |
| No Blink/Chromium bundled | Size budget enforcement: Blink ≈ 200 MB, budget = 10 MB |
| No WebExtensions compatibility layer | Absorptive architecture: features enter the kernel, not the extension store |
| WebUSB / WebMIDI permanently disabled | `sw.js` + `diatom-api.js`: physical boundary |

---

## Features

| Feature | Description |
|---|---|
| **Native ad blocking** | Aho-Corasick automaton — tracker requests are dropped before they reach the renderer |
| **Fingerprint normalisation** | Canvas / WebGL / Audio / navigator APIs normalised to the statistical mode of common desktop hardware. Deterministic per-domain, invisible to sites. |
| **E-WBN encrypted archive** | AES-256-GCM + tracker stripping + TF-IDF indexing + FTS5 full-text search. Freeze any page to your personal Museum |
| **Native RSS** | Zero plugins. RSS 2.0 / Atom parser with TF-IDF auto-tagging and reading mode |
| **Built-in 2FA** | TOTP/HOTP engine that auto-detects 2FA forms and fills in the code |
| **Local AI (Resonance Modes)** | OpenAI-compatible server at `127.0.0.1:11435`. Curated models: Qwen 2.5 3B, Phi-4 Mini, Gemma 3 4B. Other local apps (VS Code, Obsidian) can use Diatom as their AI backend |
| **The Echo** | Weekly persona spectrum (Scholar / Builder / Leisure) computed entirely on-device in a Wasm sandbox. Raw data is zeroed after computation. No data leaves the device |
| **DOM Crusher** | Ctrl+click any page element to permanently hide it. Rules persist per-domain |
| **Zen Mode** | Blocks social and entertainment sites during focus sessions. Unlocking requires typing a 50-character intent declaration — this is a ritual, not a barrier |
| **Vision Overlay** | Alt+drag to select any screen region → local Tesseract OCR → optional local translation |
| **Ghost Redirect** | When offline, semantically matches the failed URL against your personal Museum and surfaces similar archived pages |
| **Compatibility Router** | Detects broken pages and offers a clean system browser handoff (tracking parameters stripped before handing off) |
| **Accessibility** | Full ARIA injection + keyboard navigation for every chrome element |
| **Adaptive tab budget** | Three interlocking models: resource-aware scaling, golden ratio zones (Focus 61.8% / Buffer 38.2%), and screen gravity (3 tabs on phone → 13 on ultrawide) |
| **diatom://labs** | 22 experimental features — AI, privacy, performance, sync, interface — each with an honest stability and risk rating |
| **DevPanel** | Developer tools with "Open in Zed" — one click opens the current page's source file in the external Zed IDE. Resonance AI shares context with Zed via `~/.diatom/resonance.sock` |

---

## Honest limitations

Diatom has edges. We tell you where they are.

**Permanently out of scope (architecture or legal constraints):**
- Widevine L1/L3 on Linux — Google does not license the CDM to open-source projects
- Full iOS App Store distribution — Apple policy blocks custom Wasm kernels
- WebExtensions API — incompatible with the binary size budget and security model
- Bank U-Shield / NPAPI plugins — non-standard proprietary interfaces

**Filter rules (v0.11.0+):**
Diatom ships a minimal built-in blocklist. For broader coverage, use the Privacy Presets
button (or `diatom://onboarding`) to subscribe to EasyList, EasyPrivacy, or URLhaus.
Diatom is the downloader; you choose the lists.

**System browser handoff** — for these cases, `cmd_compat_handoff` strips tracking parameters before yielding the render:
- Legacy enterprise intranets with broken layout
- Banking pages requiring hardware token plugins
- DRM streaming (4K Netflix, etc.)

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
  libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Windows
# Install WebView2 Runtime (built into Windows 11)
# https://developer.microsoft.com/microsoft-edge/webview2/
```

### First run

On first launch, Diatom opens the **Onboarding Wizard** (`diatom://onboarding`):
1. Checks for Ollama (local AI)
2. Sets your privacy posture (Balanced / Strict / Minimal)
3. Subscribes to filter lists with one click
4. Shows active features

You can re-open it at any time via `diatom://onboarding`.

### Development

```bash
git clone https://github.com/Ansel-S/Diatom.git
cd Diatom
cargo tauri dev
```

### Production build

```bash
cargo tauri build
# Output: ≤ 10 MB binary
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

Once Ollama is running, Diatom auto-detects it. No configuration needed.

Resonance Mode shortcuts (address bar):
- `/scholar <question>` — answer from your local Museum only
- `/debug <code>` — architecture and code analysis
- `/scribe <draft>` — writing and editing
- `/oracle <question>` — pure logical reasoning

**Extreme Privacy Mode** — enable in `diatom://labs` to force all inference into the Wasm sandbox: no filesystem access, no network, only in-memory page content.

---

## Wasm toolbox (no network required)

Type directly in the address bar:

```
/json     Format and validate JSON
/crypto   Base64 / SHA-256 / BLAKE3 / Hex conversion
/math     Symbolic computation + unit conversion
/img      Local image compression (MozJPEG / WebP)
```

---

## Project structure

```
Diatom/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs           Tauri entry + module registration
│   │   ├── engine/           Blocker, bandwidth, ETag cache, monitor, GhostPipe, compat, plugins
│   │   ├── privacy/          PrivacyConfig, fingerprint_norm, PIR, OHTTP, onion, threat, wifi
│   │   ├── storage/          SQLite DB, vault, E-WBN freeze, storage guard, Museum versioning
│   │   ├── ai/               SLM microkernel, download renamer, shadow index, MCP host
│   │   ├── browser/          Tab lifecycle, tab limit, per-tab proxy, DOM crusher, boosts, a11y
│   │   ├── auth/             TOTP/2FA, platform passkeys, domain trust levels
│   │   ├── sync/             Nostr relay, Noise_XX P2P transport, knowledge marketplace
│   │   └── features/         Zen, RSS, panic button, breach monitor, search, pricing radar,
│   │                         ToS auditor, local file bridge, Sentinel, War Report, Labs, compliance
│   ├── resources/
│   │   └── diatom-api.js     Injected into every page
│   └── Cargo.toml
│
├── src/
│   ├── main.js               Boot sequence
│   ├── sw.js                 Service Worker (intercept + Ghost Redirect + Zen)
│   ├── index.html            Browser chrome
│   ├── diatom.css            Global styles
│   ├── browser/              Core browser modules (ipc, tabs, hotkey, lustre…)
│   ├── features/             Feature panels (echo, zen, dom-crusher…)
│   ├── workers/
│   │   └── core.worker.js   TF-IDF + OPFS + Echo scheduler + idle indexing
│   └── ui/
│       ├── about.html        diatom://about
│       └── labs.html         diatom://labs
│
├── zed-integration/          DevPanel + Resonance context bridge + Zed IDE link
│   ├── src-tauri/            Tauri commands for DevPanel, fingerprint_norm, url_stripper
│   └── zed-core/             diatom_bridge, diatom_devtools crates
│
├── AXIOMS.md                 Project axioms — inviolable constraints
├── README.md                 This file — guide + philosophy
└── LICENSE                   BUSL-1.1, Change Date 2028, Change License MIT
```

---

## Philosophy

> *"A tool with boundaries is more trustworthy than a tool that is everywhere."*

These principles shape every decision. They are documented here as rationale; as binding constraints they live in `AXIOMS.md`.

**On centralisation:** Once a server stores your history, it acquires a god's-eye view. That view can be subpoenaed, sold, or leaked. The only safe central server is one that never exists.

**On convenience trade-offs:** URL prefetch, search suggestions, predictive scrolling — these trade privacy for milliseconds. Diatom defaults to the most conservative posture. Users may opt in; they never opt out of something they never agreed to.

**On fingerprint defence:** Random noise is detectable as noise. Normalisation to the statistical mode of common hardware is invisible — millions of real devices return the same values. Determinism is the stronger defence.

**On URL stripping:** AI-generated stripping rules introduce two failure modes: removing a session token that logs the user out, or failing to recognise a novel tracker. Curated, human-reviewed Regex lists eliminate both failure modes. The rules are auditable; an AI's reasoning is not.

**On local AI:** Cloud AI means your thoughts live on someone else's server. Diatom's AI is local-only, not as a feature limitation but as a privacy guarantee with no asterisk.

**On DRM:** Widevine's absence is a deliberate boundary, not a technical problem to route around. Diatom's moral credibility depends on not cracking the CDM.

**On funding:** Firefox's greatest tragedy was Google's money. Once that dependency forms, you lose the right to call their ad network a data-pollution honeypot. Diatom's business model, if one exists, must be fully aligned with user interests.

**On attention:** "Earn tokens by watching ads" is still extracting you from the attention economy by re-selling your attention differently. Diatom's goal is extraction, not re-packaging.

---

## Contributing

Read [AXIOMS.md](AXIOMS.md) before opening a PR. Every change must pass the axioms — the CI will catch most violations automatically.

Bug reports and feature requests: [github.com/Ansel-S/Diatom/issues](https://github.com/Ansel-S/Diatom/issues)

---

## License

[Business Source License 1.1](LICENSE) — source-available, not open-source.

- Personal use, research, and contributing to this repository: **always free**
- Commercial browser products incorporating Diatom's features: **requires a separate licence**
- Change Date: 2028. After that, the code converts to **MIT** permanently.
