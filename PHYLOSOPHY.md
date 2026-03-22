# Diatom — Product Philosophy & Prohibitions

> This document is Diatom's constitution. It defines what Diatom is, and what
> Diatom will never become. Every feature, architectural decision, and partnership
> proposal must pass this document's review. If a change conflicts with any
> principle here, the change is rejected — the principle is not amended.

---

## I. Philosophical Prohibitions: Never Yield to "Convenience"

### 1. Never Build a Centralised Sync Server
No matter how loudly users complain that P2P sync is slow or requires both
devices online simultaneously — do not build a centralised cloud that stores
bookmarks or history.

Once that door opens, Diatom acquires a "god's-eye view" — the very thing
Diatom exists to eliminate. **No exceptions. No compromise paths.**

```
// Enforced at code level:
// AppState has no outbound API endpoints.
// No HTTP client calls target diatom.io or any Diatom-operated domain.
// CI check: grep -r "diatom.io\|api.diatom" src-tauri/src/ returns empty.
```

### 2. Never Add a "Skip" Button to Zen Mode
The 50-character unlock gate is a ritual, not an obstacle. It makes the act of
breaking focus conscious. A skip button destroys the feature's entire premise.

```javascript
// zen.js will never contain:
// if (emergencyBypass) return;
// if (userIsPremium) skipGate();
```

### 3. Never Enable Predictive Features by Default
URL prefetch, search suggestions, predictive scrolling — these trade privacy for
milliseconds. In Diatom, intent is completely private until the user presses Enter.
Defaults must represent the most conservative privacy posture.

---

## II. Legal Prohibitions: Never Become the Primary Liable Party

### 4. Never Officially Distribute Platform-Specific Block Rules
Diatom may publish its blocking engine (the Aho-Corasick automaton), but the
official repository will never ship `facebook.wasm` or `google-analytics.wasm`
as targeted rule files.

Diatom's legal role is "general browser technology developer", not "specific
platform traffic interceptor". Users add their own rules. Diatom does not supply them.

### 5. Never Circumvent DRM Through Unlawful Means
Widevine's absence is a real boundary, not a technical problem to route around.
External player handoff, native PlayReady/FairPlay calls — acceptable.
Cracking Widevine and bundling it — illegal and destroys Diatom's moral credibility.

---

## III. Technical Prohibitions: Never Let the Core "Bloat"

### 6. Never Let the Microkernel Absorb Business Logic
The core must stay ruthlessly clean. No matter how tempting a feature is, if it
can be hot-swapped as a module, it does not enter the kernel.

**Binary size hard ceiling: 15 MB.** Exceeding it fails CI. Pull request not merged.

### 7. Never Turn Diatom into a Chromium Wrapper
For compatibility, hand rendering control to the system WebView via Handoff.
Do not bundle a Blink/Chromium instance. That transforms 15 MB into 200 MB+,
and "precision filter" into "another Chrome".

Servo first. WebView2/WKWebView second. Blink is never touched.

### 8. Never Collect Any Form of Telemetry
"Anonymous data" does not exist. Fingerprints, timing patterns, behaviour
signatures — all data. Diatom's code calls no analytics service. We would rather
not know how many users we have than have one line of code watching user behaviour.

```rust
// These will never appear in the Diatom codebase:
// reqwest::get("https://analytics.example.com/event")
// sentry::capture_message("user_action")
```

---

## IV. Commercial Prohibitions: Never Accept "Sovereignty-Damaging" Funding

### 9. Never Accept Default Search Engine Buyout Fees
This is Firefox's greatest tragedy. Once Google's money arrives, you lose the
right to call their ad tracking network a "data pollution honeypot".
Diatom's business model, if one exists, must be fully aligned with user interests.

### 10. Never Monetise User Attention
No "earn tokens by watching ads" (Brave-style). No "sponsored content".
No "curated recommendations". Diatom's goal is to extract users from the attention
economy — not to extract them in a different way.

---

## V. Community Prohibitions: Never Become a "Digital Dictator"

### 11. Never Close-Source Core Logic
A privacy tool that is not 100% auditable is not trustworthy. Every line of code
that handles user data must be public and community-verifiable.

### 12. Never Monopolise the Module Registry
Diatom may maintain an official recommended list, but must allow users to add
third-party and decentralised module sources (e.g. IPFS-hosted registries).
We do not decide what users can install. We provide tools so users know what
they are installing.

---

## Permanent Black Zone — Design Decisions That Will Never Change

| Feature | Why it will never change |
|---------|--------------------------|
| Zen Mode 50-char gate | Ritual: removing it removes the feature itself |
| The Echo shows no flattering spin | The mirror must be honest, even when uncomfortable |
| Mesh P2P, no central server | Centralisation = god's-eye view = something that can be sold |
| WebUSB / WebMIDI disabled | The browser does not touch physical hardware. Boundary, not bug. |
| Ad-stat fingerprint pollution continues | Defence against surveillance systems needs no courtesy |
| Service Worker force-suspended | Miss a push notification before allowing background tracking surface |
| 0-RTT and prefetch disabled | Milliseconds are not worth trading for intent privacy |
| No skip buttons (anywhere) | Skip buttons are a betrayal of feature seriousness |
| Binary ≤ 15 MB hard limit | Size is the physical constraint on a lightweight promise |
| Local AI only (no cloud fallback) | Cloud AI = your thoughts on someone else's server |

---

## Version History

| Version | Change |
|---------|--------|
| v0.6.0 | Initial draft: 5 product axioms |
| v0.7.2 | Expanded: accessibility as ethical floor |
| v0.8.0 | Completed: 12 prohibitions + permanent black zone table |
| v0.9.0 | Added: Local AI sovereignty clause (prohibition 10 clarified) |

---

*"A tool with boundaries is more trustworthy than a tool that is everywhere."*
*— Diatom Design Principle*
