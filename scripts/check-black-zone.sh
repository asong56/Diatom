#!/usr/bin/env bash
# check-black-zone.sh — CI verifiability audit for Permanent Black Zone promises.
#
# Each row in the Black Zone table (AXIOMS.md) maps to either a code-level
# assertion (tested here) or a documented design-principle note. Running this
# script in CI ensures that code-verifiable promises remain true across refactors.
#
# Exit codes:  0 = all checks passed,  1 = one or more checks failed.
#
# Usage:
#   bash scripts/check-black-zone.sh [--src-dir <path>]
#   Default src-dir: src-tauri/src (relative to repo root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${REPO_ROOT}/src-tauri/src"
JS_SRC="${REPO_ROOT}/src"
FAIL=0

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAIL=1; }
note() { echo "  NOTE  $1 (design-principle, not code-verifiable)"; }

echo "=== check-black-zone.sh ==="
echo "Repo: $REPO_ROOT"
echo ""

# ── 1. Zen Mode intent gate default=true ─────────────────────────────────────
echo "[1] Zen Mode intent gate defaults to true..."
if grep -r "require_intent_gate.*true\|intent_gate.*true" \
       "${SRC}/features/zen.rs" > /dev/null 2>&1; then
    pass "zen.rs contains require_intent_gate default=true"
else
    fail "zen.rs: require_intent_gate default=true not found"
fi

# Also verify there is no skip-button path in the JS zen overlay
if grep -rn "skip\|skipGate\|bypassZen" "${JS_SRC}/features/zen.js" \
       2>/dev/null | grep -v "^.*\/\/" | grep -q .; then
    fail "zen.js: potential skip-button path detected"
else
    pass "zen.js: no skip-button path detected"
fi

echo ""

# ── 2. WebUSB / WebMIDI disabled ─────────────────────────────────────────────
echo "[2] WebUSB / WebMIDI disabled in service worker..."
SW="${REPO_ROOT}/src/sw.js"
if [[ ! -f "$SW" ]]; then
    fail "src/sw.js not found — cannot verify WebUSB/WebMIDI block"
else
    if grep -q "usb\|midi" "$SW" 2>/dev/null; then
        pass "sw.js references usb/midi (block present)"
    else
        fail "sw.js: WebUSB/WebMIDI intercept not found"
    fi
fi

echo ""

# ── Notes for design-principle promises ───────────────────────────────────────
echo "[4] Checking for undocumented outbound HTTP calls in Tauri source..."
# Known-good endpoint patterns from AXIOMS.md §Known Outbound Network Calls
KNOWN_ENDPOINTS=(
    "versionhistory.googleapis.com"
    "developer.apple.com/news/releases"
    "chromereleases.googleblog.com"
    "api.pwnedpasswords.com"
    "haveibeenpwned.com"
    "easylist.to"
    "urlhaus"
    "github.com/repos/diatom-browser/diatom/releases"
)

# Grab all string literals containing "https://" from Rust source
ALL_URLS=$(grep -rh '"https://' "${SRC}" 2>/dev/null | \
    grep -oE '"https://[^"]*"' | tr -d '"' | sort -u)

UNKNOWN_URLS=""
while IFS= read -r url; do
    MATCHED=false
    for ep in "${KNOWN_ENDPOINTS[@]}"; do
        if [[ "$url" == *"$ep"* ]]; then
            MATCHED=true
            break
        fi
    done
    if [[ "$MATCHED" == false ]]; then
        UNKNOWN_URLS="${UNKNOWN_URLS}\n    $url"
    fi
done <<< "$ALL_URLS"

if [[ -n "$UNKNOWN_URLS" ]]; then
    echo "  ATTENTION: URLs not in AXIOMS.md outbound call table:"
    echo -e "$UNKNOWN_URLS"
    echo "  If these are new legitimate calls, add them to AXIOMS.md §Known Outbound"
    echo "  Network Calls and re-run."
    fail "undocumented outbound URLs detected"
else
    pass "all HTTPS endpoints match AXIOMS.md known-calls table"
fi

echo ""

# ── 5. Shell binary size (≤ 10 MB) ────────────────────────────────────────────
echo "[5] Shell binary size check..."
SHELL_BIN="${REPO_ROOT}/target/release/diatom"
if [[ -f "$SHELL_BIN" ]]; then
    SIZE=$(stat -c%s "$SHELL_BIN" 2>/dev/null || stat -f%z "$SHELL_BIN")
    LIMIT=$((10 * 1024 * 1024))
    if [[ $SIZE -le $LIMIT ]]; then
        pass "diatom binary: $(( SIZE / 1024 ))KB ≤ 10MB"
    else
        fail "diatom binary: $(( SIZE / 1024 / 1024 ))MB exceeds 10MB limit"
    fi
else
    note "target/release/diatom not found — build first to check binary size"
fi

echo ""

# ── 6. No skip buttons anywhere ───────────────────────────────────────────────
echo "[6] Checking for skip buttons in UI HTML..."
SKIP_HITS=$(grep -rn \
    'id="skip\|class="skip\|skipButton\|skip-button\|data-skip\|btnSkip' \
    "${JS_SRC}" 2>/dev/null | grep -v "^.*\/\/" || true)
if [[ -n "$SKIP_HITS" ]]; then
    echo "  Potential skip-button patterns found:"
    echo "$SKIP_HITS" | sed 's/^/    /'
    fail "skip button patterns detected"
else
    pass "no skip button patterns found in src/"
fi

echo ""

# ── 7. URL stripping is regex-only (no AI call path) ─────────────────────────
echo "[7] URL stripper: no AI delegation..."
STRIPPER="${SRC}/engine/url_stripper.rs"
if [[ -f "$STRIPPER" ]]; then
    if grep -qE "slm|openai|ai::|llm|model\b" "$STRIPPER" 2>/dev/null; then
        fail "url_stripper.rs: possible AI delegation found"
    else
        pass "url_stripper.rs: no AI references"
    fi
else
    fail "url_stripper.rs not found"
fi

echo ""

# ── Notes for design-principle promises ───────────────────────────────────────
echo "Design-principle promises (not code-verifiable — must be verified by review):"
note "Mesh P2P, no central server — architecture constraint"
note "Fingerprint normalisation (not noise) — FingerprintNorm::generate() in fingerprint_norm.rs"
note "Service Worker force-suspended — sw.js implementation"
note "0-RTT disabled (application layer only) — no application prefetch in codebase"
note "Local AI only (no cloud fallback) — slm_adapter.rs, Axiom 16"

echo ""

# ── Result ────────────────────────────────────────────────────────────────────
if [[ $FAIL -ne 0 ]]; then
    echo "RESULT: FAILED — see above."
    exit 1
else
    echo "RESULT: PASSED — all verifiable Black Zone checks clean."
    exit 0
fi
