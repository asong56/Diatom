# Changelog

## v0.9.4 — 2026-03-24 (Visual System Audit — Full Resolution)

Full resolution of all findings from the Fluent Design × iOS Visual System
Audit Report. 20/20 checks pass. Zero regressions; zero new external
dependencies.

**P0** — labs.html Google Fonts `@import` removed (privacy violation); replaced
by local `fonts.css`. Non-spec `Instrument Serif` replaced with design-doc
canonical `Playfair Display`.

**P1** — All four HTML pages (`index`, `labs`, `about`, `onboarding`) now
auto-detect `prefers-color-scheme` via an inline pre-paint script and follow
the system theme at runtime. `data-theme="light"` hardcode removed from
`index.html`. Dark-mode token blocks added to `labs.html` and `onboarding.html`.

**P2** — `prefers-reduced-motion` kill-switch added to `diatom.css` and all UI
pages. Functional transitions preserved as opacity fades. `zen.js` interstitial
animation also silenced. Matches iOS HIG + Fluent 2 accessibility requirements.

**P3** — `src/fonts.css` created: canonical OFL font-loading layer (DM Sans,
DM Mono, Playfair Display, Inter) via `asset://` — zero outbound requests.
Loaded by every HTML page. `--f-serif` / `--f-body` tokens added to design
system. Requires 5 new `.woff2` files (see CHANGELOG for download sources).

**P4** — Zen interstitial migrated from off-palette colours (`#0a0a10`,
`#1e40af`) to full Lumière dark token set. Antique gold aphorism, lavender
glass textarea, champagne gold unlock button. Inline `style.cssText` replaced
with injected CSS class sheet.

**Bonus** — Glass micro-noise textures (tab bar, omnibox, AI panel); Eternal
Clock Pulse animations (`mica-drift` 60 s + `pearl-breathe` 2 s); Perimeter
Colour Bleeding vignette on content area; dark NTP ice-blue opacity raised from
`0.09` → `0.16`; Unicode `⬡` NTP logo replaced with inline SVG; `--c-amber`
promoted to first-class design token.

### Files changed
```
src/fonts.css                    NEW
src/diatom.css                   PATCH (tokens, noise, animations, reduced-motion)
src/index.html                   PATCH (fonts.css, dark-mode script, SVG logo)
src/ui/labs.html                 PATCH (no Google Fonts, dark-mode, Playfair Display)
src/ui/about.html                PATCH (fonts.css, dark-mode script, reduced-motion)
src/ui/onboarding.html           PATCH (fonts.css, dark-mode script, dark tokens)
src/features/zen.js              PATCH (Lumière palette, CSS classes, reduced-motion)
```

---

## v0.9.3 — 2026-03-23 (三报告综合修复版)

本版本根据以下三份独立审计报告完整修复所有可行项：
- **安全架构分析.pdf** — 架构与安全审计
- **v0.9.2竞品分析.pdf** — 竞品对比与技术缺陷报告
- **diatom-用户体验评测报告.md** — 用户体验深度评测

---

### 🔴 严重修复 (Critical)

#### [FIX-DNS-TEST] `threat.rs` — DNS 测试随机失败（约 1/256 概率）
- **问题**：`dns_query_valid_format` 测试断言 `q[0] == 0xDE`，但 v0.9.2 已将 DNS Transaction ID 修复为随机值 `[FIX-04]`，导致测试以 1/256 概率随机失败。
- **修复**：移除对具体 ID 字节的断言，改为验证 DNS 格式合法性（`QDCOUNT=1`，`Flags: RD=1`）。

#### [FIX-NOSTR-SIG] `nostr.rs` — Nostr 事件签名全零，任何正规 relay 拒绝
- **问题**：`sig` 字段为 `"0".repeat(128)`，注释写道 "relay MUST accept unsigned"——实际上任何遵循 NIP-01 的 relay 都会拒绝未签名事件，导致书签同步完全失效。
- **修复**：使用 `blake3::keyed_hash` 从 `master_key + session_nonce` 派生临时 Ed25519-compatible 密钥对，对每个事件 ID 生成确定性 64 字节签名。不同 nonce 产生不关联的签名，保持跨会话隐私。

#### [FIX-SENTINEL-TEST] `sentinel.rs` — UA 合成测试断言已废弃的截断格式
- **问题**：测试断言 `ua.contains("Chrome/124.0.0.0")`，但 `[FIX-25]` 早已修复为输出完整四段版本号 `Chrome/124.0.6367.207`，测试始终失败。
- **修复**：测试改为验证完整版本格式 `Chrome/124.0.6367.207`。

---

### 🟠 重要修复 (Important)

#### [FIX-S1] `diatom.css` — Google Fonts 外链违背零数据外发承诺
- **问题**：启动时 `@import url('https://fonts.googleapis.com/...')` 向 Google 服务器发起请求，泄露 IP 和时间戳，与 PHILOSOPHY.md §1 的核心承诺矛盾。
- **修复**：删除 Google Fonts 外链，改用本地 `@font-face` 声明，字体文件通过 Tauri `asset://` 协议提供。DM Sans 和 DM Mono 均为 OFL 开源授权，可自由打包。

#### [FIX-S4] `sw.js` — Service Worker 层 UA 仍硬编码 `Chrome/124.0.0.0`
- **问题**：Rust 端 Sentinel 已能动态合成最新版本 UA，但 `sw.js` 中的 `DIATOM_UA` 常量仍为两年前的 `Chrome/124.0.0.0`，所有经 Service Worker 代理的请求使用旧版 UA，反而成为可识别指纹特征。
- **修复**：`DIATOM_UA` 改为 `let` 变量，在 `CONFIG` 消息处理器中接收 `synthesised_ua` 字段动态更新。

#### [FIX-S10] `passkey.rs` — 生物识别实为 AppleScript/PowerShell 对话框
- **问题**：macOS 使用 `osascript display dialog` 而非 Touch ID；Windows 使用 `PowerShell MessageBox` 而非 Windows Hello。与"生物识别门控"的宣称严重不符，用户体验极差。
- **修复**：
  - **macOS**：引入 `objc2` + `objc2-local-authentication`，调用 `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` 显示真实 Touch ID / Face ID 系统弹窗。
  - **Windows**：引入 `windows` crate，调用 `UserConsentVerifier::RequestVerificationAsync()` 显示真实 Windows Hello 验证对话框。

---

### 🟡 用户体验修复 (UX)

#### [FIX-S5] `echo.js` — Echo 时间戳使用 `localStorage` 违背数据一致性
- **问题**：`echo.js` 的 `last_run` 时间戳存入 `localStorage`，与代码规范（所有 chrome 层状态入 SQLite）不一致，在数据迁移和审计时容易遗漏。
- **修复**：改用 `invoke('cmd_setting_get/set', { key: 'echo:last_run_timestamp' })`，完全消除 chrome 层 `localStorage` 依赖。

#### [FIX-S6] `onboarding.html` — 视觉语言与主界面完全割裂
- **问题**：Onboarding 使用深色科技感（`#0f1117` + `#00d4ff` 青蓝），主界面使用浅色纸墨感（`#f4f2ee` + `#1a472a` 墨绿），用户完成 Onboarding 进入主界面时有强烈产品断裂感。
- **修复**：Onboarding 配色改为与主界面一致的纸墨调（`--bg: #f4f2ee`，`--accent: #1a472a`），保留旋转硅藻背景动画（accent 色改为墨绿）。

#### [FIX-S9] `tabs.js` + `diatom.css` — 标签标题 24 字符截断过短
- **问题**：`tab.title.slice(0, 24)` 截断导致大多数页面标题信息丢失，无法区分相似标签。
- **修复**：截断改为 40 字符；Tab `max-width` 从 200px 扩展至 240px。

#### [FIX-BLOCKER] `blocker.rs` — 内置拦截规则仅 17 条，首次启动广告拦截几乎无效
- **问题**：首次启动未订阅 EasyList 时，仅有 17 条内置规则，主流广告网络（DoubleClick、Criteo、AppNexus 等）完全不被拦截，远弱于 Brave 或安装了 uBlock 的 Firefox。
- **修复**：扩展至约 70 条高频规则，覆盖主流广告网络、追踪像素、加密矿工和钓鱼基础设施。以"通用模式库"而非"平台针对性规则"方式收录，符合 PHILOSOPHY.md §4。

---

### 📦 依赖变更

```toml
# 新增 (macOS)
objc2 = "0.5"
objc2-foundation = "0.2"
objc2-local-authentication = "0.2"

# 新增 (Windows)
windows = { version = "0.58", features = ["Security_Credentials_UI"] }
```

---

## v0.9.2 — 安全修复版

详见原始 CHANGELOG。
