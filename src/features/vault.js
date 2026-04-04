// ─────────────────────────────────────────────────────────────────────────────
// diatom/src/features/vault.js  — v0.9.5
//
// Vault integration for the main browser chrome.
// Responsibilities:
//   • Detect password fields on the current page domain → offer autofill
//   • Show TOTP code overlay when autofilling (matches totp.match_domain)
//   • Trigger vault panel open (opens vault.html in a sidebar pane)
//   • Export a VaultAutofill API consumed by diatom-api.js
//
// Architecture: This module runs in the Diatom chrome (not injected into
// the WebView page). It communicates via the Tauri IPC bridge.
// ─────────────────────────────────────────────────────────────────────────────

import { invoke } from '../browser/ipc.js';

// ── Autofill chip ─────────────────────────────────────────────────────────────

const CHIP_ID = '__diatom_vault_chip__';
let currentDomain = '';
let pendingLogins  = [];

/**
 * Called by the tab navigation handler when the user navigates to a new URL.
 * Checks for matching vault entries and shows a subtle autofill offer.
 */
export async function onNavigate(url) {
  removeChip();

  let domain;
  try { domain = new URL(url).hostname; } catch { return; }
  currentDomain = domain;

  // Parallel: check vault logins and TOTP codes for this domain
  const [matchedLogins, matchedTotp] = await Promise.all([
    invoke('cmd_vault_match_domain', { domain }).catch(() => []),
    invoke('cmd_totp_match', { domain }).catch(() => []),
  ]);

  pendingLogins = matchedLogins;

  if (matchedLogins.length === 0 && matchedTotp.length === 0) return;

  showAutofillChip(matchedLogins, matchedTotp);
}

function showAutofillChip(logins, totps) {
  const chip = document.createElement('div');
  chip.id = CHIP_ID;
  chip.style.cssText = `
    position: fixed; bottom: 20px; right: 20px; z-index: 99999;
    background: #151720; border: 1px solid #2a2d3a;
    border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.5);
    padding: 12px 16px; display: flex; align-items: center; gap: 10px;
    font-family: system-ui, sans-serif; font-size: 13px;
    color: #e2e8f0; cursor: pointer; transition: border .15s;
    max-width: 300px; animation: slideUp .2s ease;
  `;

  const icon = logins.length ? '🔑' : '⏱';
  const label = logins.length
    ? `${logins.length} login${logins.length > 1 ? 's' : ''} found`
    : `${totps.length} 2FA code${totps.length > 1 ? 's' : ''} found`;

  chip.innerHTML = `
    <span style="font-size:18px">${icon}</span>
    <div style="flex:1">
      <div style="font-weight:600;color:#00d4ff">${label}</div>
      <div style="color:#94a3b8;font-size:11px;margin-top:1px">Click to autofill</div>
    </div>
    <button style="background:none;border:none;color:#475569;cursor:pointer;
      padding:2px 4px;border-radius:4px;font-size:14px;line-height:1"
      onclick="event.stopPropagation(); this.closest('#${CHIP_ID}').remove()">✕</button>
  `;

  chip.addEventListener('click', () => {
    if (logins.length) showAutofillPicker(logins, totps);
    else if (totps.length) showTotpPicker(totps);
  });

  // Auto-dismiss after 8 seconds
  const dismissTimer = setTimeout(() => chip.remove(), 8000);
  chip.addEventListener('mouseenter', () => clearTimeout(dismissTimer));

  document.body.appendChild(chip);

  // Inject keyframe if not already done
  if (!document.getElementById('__diatom_vault_style__')) {
    const style = document.createElement('style');
    style.id = '__diatom_vault_style__';
    style.textContent = `
      @keyframes slideUp { from { opacity:0; transform:translateY(8px) } to { opacity:1; transform:none } }
      @keyframes fadeIn  { from { opacity:0 } to { opacity:1 } }
    `;
    document.head.appendChild(style);
  }
}

function removeChip() {
  document.getElementById(CHIP_ID)?.remove();
}

// ── Autofill picker ───────────────────────────────────────────────────────────

function showAutofillPicker(logins, totps) {
  removeChip();
  const overlay = createOverlay();

  const box = document.createElement('div');
  box.style.cssText = `
    background:#151720; border:1px solid #2a2d3a; border-radius:14px;
    padding:16px; width:320px; max-height:420px; overflow-y:auto;
    box-shadow:0 8px 40px rgba(0,0,0,.6); animation:fadeIn .15s ease;
    font-family:system-ui,sans-serif; color:#e2e8f0;
  `;

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:600;font-size:13px;color:#94a3b8;margin-bottom:10px;padding:0 2px';
  title.textContent = `Logins for ${currentDomain}`;
  box.appendChild(title);

  logins.forEach(login => {
    const row = document.createElement('div');
    row.style.cssText = `
      display:flex; align-items:center; gap:10px; padding:10px 12px;
      border-radius:8px; cursor:pointer; transition:background .12s;
    `;
    row.addEventListener('mouseenter', () => row.style.background = '#1d1f2a');
    row.addEventListener('mouseleave', () => row.style.background = '');
    row.innerHTML = `
      <div style="width:32px;height:32px;border-radius:8px;background:#1d1f2a;
        border:1px solid #2a2d3a;display:flex;align-items:center;justify-content:center;
        font-size:14px">${getInitial(login.title)}</div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${login.title}</div>
        <div style="color:#94a3b8;font-size:11px;margin-top:1px;white-space:nowrap;
          overflow:hidden;text-overflow:ellipsis">${login.username}</div>
      </div>
      ${login.has_totp ? '<span style="font-size:10px;padding:2px 6px;border-radius:10px;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:#00d4ff">2FA</span>' : ''}
    `;
    row.addEventListener('click', () => doAutofill(login.id, totps, overlay));
    box.appendChild(row);
  });

  if (totps.length && !logins.length) {
    showTotpInBox(box, totps);
  }

  overlay.appendChild(box);
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

async function doAutofill(loginId, totps, overlay) {
  overlay?.remove();
  try {
    const authed = await invoke('cmd_local_auth', { reason: 'Autofill password' });
    if (!authed) { showToast('Authentication required', 'err'); return; }

    const entry = await invoke('cmd_vault_login_get', { id: loginId });

    // Try to fill username/password fields in the page using postMessage
    // (the page's diatom-api.js handles the actual DOM manipulation)
    window.dispatchEvent(new CustomEvent('diatom:vault-autofill', {
      detail: { username: entry.username, password: entry.password }
    }));

    // Copy password to clipboard as fallback
    await navigator.clipboard.writeText(entry.password).catch(() => {});

    showToast(`Autofilled ${entry.title}`, 'ok');

    // Show TOTP if available
    if (totps.length) {
      setTimeout(() => showTotpPicker(totps), 500);
    }
  } catch(e) {
    showToast('Autofill failed', 'err');
  }
}

// ── TOTP picker ───────────────────────────────────────────────────────────────

function showTotpPicker(totps) {
  const overlay = createOverlay();
  const box = document.createElement('div');
  box.style.cssText = `
    background:#151720; border:1px solid #2a2d3a; border-radius:14px;
    padding:16px; width:300px; box-shadow:0 8px 40px rgba(0,0,0,.6);
    animation:fadeIn .15s ease; font-family:system-ui,sans-serif; color:#e2e8f0;
  `;

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:600;font-size:13px;color:#94a3b8;margin-bottom:12px';
  title.textContent = '2FA Codes';
  box.appendChild(title);

  showTotpInBox(box, totps);
  overlay.appendChild(box);
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

function showTotpInBox(box, totps) {
  totps.forEach(totp => {
    const row = document.createElement('div');
    row.style.cssText = `
      display:flex; align-items:center; gap:12px; padding:10px 0;
      border-bottom:1px solid #2a2d3a; cursor:pointer;
    `;

    // Countdown ring
    const period = totp.period ?? 30;
    const remaining = period - (Math.floor(Date.now() / 1000) % period);
    const pct = remaining / period;
    const r = 18; const circ = 2 * Math.PI * r;

    row.innerHTML = `
      <div style="position:relative;width:44px;height:44px;flex-shrink:0">
        <svg width="44" height="44" viewBox="0 0 44 44">
          <circle cx="22" cy="22" r="${r}" fill="none" stroke="#1d1f2a" stroke-width="3"/>
          <circle cx="22" cy="22" r="${r}" fill="none" stroke="#00d4ff" stroke-width="3"
            stroke-dasharray="${circ}" stroke-dashoffset="${circ * (1 - pct)}"
            stroke-linecap="round" transform="rotate(-90 22 22)"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;align-items:center;
          justify-content:center;font-size:10px;font-weight:700;color:#00d4ff;
          font-family:monospace">${remaining}</div>
      </div>
      <div style="flex:1">
        <div style="font-size:11px;color:#94a3b8;margin-bottom:2px">
          ${totp.issuer}${totp.account ? ' · ' + totp.account : ''}</div>
        <div style="font-family:monospace;font-size:1.4rem;font-weight:700;
          letter-spacing:.2em;color:#e2e8f0">${totp.code}</div>
        <div style="font-size:10px;color:#475569;margin-top:1px">Next: ${totp.next_code}</div>
      </div>
      <button style="background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);
        color:#00d4ff;border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;
        font-weight:600" data-code="${totp.code}">Copy</button>
    `;
    row.querySelector('button').addEventListener('click', async e => {
      e.stopPropagation();
      await navigator.clipboard.writeText(e.target.dataset.code).catch(() => {});
      showToast('Code copied!', 'ok');
    });
    box.appendChild(row);
  });
}

// ── Overlay helper ────────────────────────────────────────────────────────────

function createOverlay() {
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position:fixed; inset:0; z-index:99998;
    background:rgba(0,0,0,.5); backdrop-filter:blur(4px);
    display:flex; align-items:center; justify-content:center;
  `;
  return overlay;
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(msg, type = 'ok') {
  const el = document.createElement('div');
  el.style.cssText = `
    position:fixed; bottom:20px; right:20px; z-index:100000;
    background:#151720; border:1px solid ${type === 'ok' ? '#22c55e' : '#ff4b6e'};
    color:${type === 'ok' ? '#22c55e' : '#ff4b6e'};
    border-radius:8px; padding:10px 16px; font-size:13px;
    font-family:system-ui,sans-serif; box-shadow:0 4px 24px rgba(0,0,0,.5);
    animation:slideUp .2s ease;
  `;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

// ── Vault panel opener ────────────────────────────────────────────────────────

/**
 * Open the Vault management page in a new tab.
 * Called from the toolbar vault button or keyboard shortcut.
 */
export function openVaultPanel() {
  window.dispatchEvent(new CustomEvent('diatom:open-tab', {
    detail: { url: 'diatom://vault', title: 'Vault' }
  }));
}

// ── Password generator (accessible from page context via event) ───────────────

window.addEventListener('diatom:generate-password', async e => {
  try {
    const cfg = e.detail ?? {};
    const pw = await invoke('cmd_vault_generate_password', {
      cfg: { length: cfg.length ?? 20, uppercase: true, numbers: true, symbols: true }
    });
    window.dispatchEvent(new CustomEvent('diatom:generated-password', { detail: pw }));
  } catch {}
});

// ── Utilities ─────────────────────────────────────────────────────────────────

function getInitial(title) {
  return (title ?? '?')[0]?.toUpperCase() ?? '🔑';
}

export default { onNavigate, openVaultPanel };
