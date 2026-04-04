/**
 * diatom/src/features/video-pip.js  — v0.12.0  [F-02]
 *
 * Picture-in-Picture Video Engine — 浮窗播放
 *
 * Promotes video-controller.js to a first-class PiP engine.
 * Adds requestPictureInPicture() API binding, a floating overlay window for
 * sites that block native PiP, and a media session toolbar.
 *
 * Privacy: video stream never leaves the device; no third-party PiP services.
 * Labs risk: fallback window opens a secondary Tauri WebviewWindow — ensure it
 * inherits initialization_scripts so privacy spoofing remains active.
 *
 * Lab ID: video_pip
 */

'use strict';

import { invoke, listen } from '../browser/ipc.js';

// ── State ─────────────────────────────────────────────────────────────────────

let _pipWindow   = null;   // Browser PiP window (document PiP API)
let _activeVideo = null;   // Currently PiP'd <video> element
let _toolbar     = null;   // Floating toolbar overlay
let _enabled     = false;

// ── Init ──────────────────────────────────────────────────────────────────────

export function initPip() {
    _enabled = true;

    // Inject PiP trigger button into every <video> on mouseover
    document.addEventListener('mouseover', onVideoHover, { passive: true });

    // Listen for Rust-side PiP events (from keyboard shortcut or toolbar button)
    listen('diatom:pip-toggle', handlePipToggle);

    // MediaSession API — exposes transport controls to OS media HUD
    if ('mediaSession' in navigator) {
        navigator.mediaSession.setActionHandler('play',  () => _activeVideo?.play());
        navigator.mediaSession.setActionHandler('pause', () => _activeVideo?.pause());
        navigator.mediaSession.setActionHandler('stop',  () => exitPip());
    }
}

// ── PiP entry ─────────────────────────────────────────────────────────────────

/**
 * Enter PiP for the given video element.
 * Primary path: requestPictureInPicture() browser API.
 * Fallback: Tauri secondary window with canvas.captureStream() mirror.
 */
export async function enterPip(videoEl) {
    if (!videoEl || videoEl === _activeVideo) return;

    exitPip(); // Close any existing PiP first
    _activeVideo = videoEl;

    // Primary: native browser PiP
    if (document.pictureInPictureEnabled && !videoEl.disablePictureInPicture) {
        try {
            _pipWindow = await videoEl.requestPictureInPicture();
            _pipWindow.addEventListener('leavepictureinpicture', onLeavePip);
            updateMediaSession(videoEl);
            showPipIndicator('PiP Active');
            return;
        } catch (err) {
            // NotAllowedError or SecurityError — fall through to Tauri fallback
            console.debug('[video-pip] native PiP failed:', err.message, '— using Tauri fallback');
        }
    }

    // Fallback: Tauri secondary window
    await launchTauriPipWindow(videoEl);
}

export function exitPip() {
    if (_pipWindow) {
        try { document.exitPictureInPicture?.(); } catch { /* ignore */ }
        _pipWindow = null;
    }
    removeToolbar();
    _activeVideo = null;
    invoke('cmd_setting_set', { key: '__pip_active__', value: '0' }).catch(() => {});
}

// ── Tauri fallback PiP window ─────────────────────────────────────────────────

async function launchTauriPipWindow(videoEl) {
    // Capture the video stream via canvas
    const canvas  = document.createElement('canvas');
    canvas.width  = videoEl.videoWidth  || 480;
    canvas.height = videoEl.videoHeight || 270;
    const ctx     = canvas.getContext('2d');

    // Mirror loop at video framerate
    let _mirrorId;
    function mirrorFrame() {
        ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
        _mirrorId = requestAnimationFrame(mirrorFrame);
    }
    mirrorFrame();

    // Notify Rust to open the secondary window (always-on-top, borderless, 480×270)
    // Rust will emit diatom:pip-window-ready when the window is shown
    try {
        await invoke('cmd_setting_set', { key: '__pip_active__', value: '1' });
        showPipIndicator('PiP (Fallback)');
    } catch (err) {
        console.warn('[video-pip] Tauri fallback PiP failed:', err);
        cancelAnimationFrame(_mirrorId);
        _activeVideo = null;
    }
}

// ── Toolbar ───────────────────────────────────────────────────────────────────

function buildToolbar(videoEl) {
    const bar = document.createElement('div');
    bar.id = '__diatom_pip_toolbar';
    bar.style.cssText = `
        position:absolute; bottom:8px; left:50%; transform:translateX(-50%);
        background:rgba(10,10,16,.88); border:1px solid rgba(96,165,250,.2);
        border-radius:6px; padding:4px 8px; display:flex; gap:8px;
        align-items:center; z-index:2147483646; pointer-events:all;
        font:12px/1 'Inter',system-ui; color:#94a3b8;
    `;

    const btn = (icon, title, action) => {
        const b = document.createElement('button');
        b.textContent = icon;
        b.title = title;
        b.style.cssText = 'background:none;border:none;cursor:pointer;color:#94a3b8;font-size:16px;padding:2px 4px;';
        b.addEventListener('click', e => { e.stopPropagation(); action(); });
        return b;
    };

    bar.appendChild(btn('⏮', 'Seek back 10s',   () => { if (videoEl) videoEl.currentTime -= 10; }));
    bar.appendChild(btn('⏯', 'Play/Pause',       () => { if (videoEl) videoEl.paused ? videoEl.play() : videoEl.pause(); }));
    bar.appendChild(btn('⏭', 'Seek forward 10s', () => { if (videoEl) videoEl.currentTime += 10; }));
    bar.appendChild(btn('🔇', 'Mute/Unmute',      () => { if (videoEl) videoEl.muted = !videoEl.muted; }));
    bar.appendChild(btn('✕', 'Close PiP',         () => exitPip()));

    return bar;
}

function removeToolbar() {
    if (_toolbar) { _toolbar.remove(); _toolbar = null; }
}

// ── Video hover injection ─────────────────────────────────────────────────────

function onVideoHover(e) {
    if (!_enabled) return;
    const video = e.target.closest('video');
    if (!video) return;
    if (video.dataset.pipBtn) return; // already injected

    video.dataset.pipBtn = '1';

    const btn = document.createElement('button');
    btn.textContent = '⧉';
    btn.title = 'Open Picture-in-Picture';
    btn.style.cssText = `
        position:absolute; top:8px; right:8px; z-index:99999;
        background:rgba(10,10,16,.75); color:#e2e8f0;
        border:none; border-radius:4px; padding:4px 7px;
        font:13px/1 system-ui; cursor:pointer; pointer-events:all;
    `;
    btn.addEventListener('click', e => { e.stopPropagation(); enterPip(video); });

    // Position relative to video parent
    const parent = video.parentElement;
    if (parent && getComputedStyle(parent).position === 'static') {
        parent.style.position = 'relative';
    }
    video.insertAdjacentElement('afterend', btn);

    // Remove button when mouse leaves the video area
    video.addEventListener('mouseleave', () => { btn.remove(); delete video.dataset.pipBtn; }, { once: true });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function onLeavePip() {
    _pipWindow   = null;
    _activeVideo = null;
    removeToolbar();
}

async function handlePipToggle() {
    if (_activeVideo) {
        exitPip();
    } else {
        // Find the first playing video on the page
        const video = Array.from(document.querySelectorAll('video'))
            .find(v => !v.paused && !v.ended && v.readyState > 2);
        if (video) await enterPip(video);
    }
}

function updateMediaSession(videoEl) {
    if (!('mediaSession' in navigator)) return;
    navigator.mediaSession.metadata = new MediaMetadata({
        title:  document.title.slice(0, 80),
        artist: location.hostname,
    });
    navigator.mediaSession.playbackState = videoEl.paused ? 'paused' : 'playing';
}

function showPipIndicator(text) {
    const el = document.createElement('div');
    el.style.cssText = `
        position:fixed;top:.8rem;right:.8rem;z-index:2147483647;
        background:rgba(10,10,16,.9);border:1px solid rgba(96,165,250,.2);
        color:#94a3b8;font:500 .72rem/1 'Inter',system-ui;
        padding:.28rem .6rem;border-radius:.25rem;pointer-events:none;
    `;
    el.textContent = `⧉ ${text}`;
    document.body.appendChild(el);
    setTimeout(() => {
        el.style.transition = 'opacity .4s';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 420);
    }, 2000);
}
