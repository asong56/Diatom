
'use strict';

import { invoke } from './ipc.js';
import { domainOf } from './utils.js';

const FULL_YIELD_DOMAINS = new Set([
  'figma.com', 'sketch.com', 'canva.com', 'adobe.com', 'framer.com',
  'excalidraw.com', 'miro.com', 'whimsical.com', 'www.canva.com',
  'codepen.io', 'codesandbox.io', 'stackblitz.com', 'replit.com',
  'vscode.dev', 'github.dev', 'gitpod.io', 'glitch.com',
  'ssh.online-convert.com', 'ttyd.github.io',
  'descript.com', 'kapwing.com',
]);

const PARTIAL_YIELD_DOMAINS = new Set([
  'notion.so', 'www.notion.so', 'linear.app', 'clickup.com',
  'app.asana.com', 'trello.com', 'airtable.com',
  'docs.google.com', 'sheets.google.com', 'slides.google.com',
  'onedrive.live.com', 'office.com',
  'app.slack.com', 'discord.com', 'teams.microsoft.com',
]);

const PARTIAL_YIELD_KEYS = new Set(['s', 'w', 'b', 'i', 'k', 'z']);

let _currentDomain  = '';
let _yieldLevel     = 'NORMAL';          // 'FULL_YIELD' | 'PARTIAL_YIELD' | 'NORMAL'
let _userYieldDomains = new Set();        // loaded from settings
let _registeredHandlers = new Map();     // key → { handler, description }
let _altDown = false;
let _visionActive = false;

export async function initHotkeys() {
  try {
    const raw = await invoke('cmd_setting_get', { key: 'hotkey_yield_domains' });
    if (raw) JSON.parse(raw).forEach(d => _userYieldDomains.add(d));
  } catch { /* settings not yet populated */ }

  document.addEventListener('keydown', onKeyDown, { capture: true });
  document.addEventListener('keyup',   onKeyUp,   { capture: true });
}

export function updateContext(url) {
  _currentDomain = domainOf(url);
  _yieldLevel = classifyDomain(_currentDomain);

  if (_yieldLevel === 'FULL_YIELD' && _visionActive) {
    cancelVisionIfActive();
  }
}

function classifyDomain(domain) {
  if (_userYieldDomains.has(domain)) return 'FULL_YIELD';
  if (FULL_YIELD_DOMAINS.has(domain)) return 'FULL_YIELD';
  if (PARTIAL_YIELD_DOMAINS.has(domain)) return 'PARTIAL_YIELD';
  return 'NORMAL';
}

export function register(id, binding, handler, opts = {}) {
  _registeredHandlers.set(id, {
    binding,
    handler,
    yieldInPartial: opts.yieldInPartial !== false,
  });
}

export function unregister(id) {
  _registeredHandlers.delete(id);
}

function onKeyDown(e) {
  if (e.key === 'Alt') { _altDown = true; }

  if (_yieldLevel === 'FULL_YIELD') return;

  for (const [id, { binding, handler, yieldInPartial }] of _registeredHandlers) {
    if (!matchesBinding(e, binding)) continue;

    if (_yieldLevel === 'PARTIAL_YIELD' && yieldInPartial) {
      if (PARTIAL_YIELD_KEYS.has(e.key.toLowerCase())) return;
    }

    e.preventDefault();
    e.stopPropagation();
    handler(e);
    return;
  }
}

function onKeyUp(e) {
  if (e.key === 'Alt') {
    _altDown = false;
    _visionActive = false;
  }
}

function matchesBinding(e, b) {
  return e.key.toLowerCase() === b.key.toLowerCase()
    && !!e.ctrlKey  === !!b.ctrl
    && !!e.altKey   === !!b.alt
    && !!e.shiftKey === !!b.shift
    && !!e.metaKey  === !!b.meta;
}

function cancelVisionIfActive() {
  document.dispatchEvent(new CustomEvent('diatom:cancel-vision'));
}

export async function yieldCurrentDomain() {
  _userYieldDomains.add(_currentDomain);
  _yieldLevel = 'FULL_YIELD';
  await invoke('cmd_setting_set', {
    key:   'hotkey_yield_domains',
    value: JSON.stringify([..._userYieldDomains]),
  });
}

export function getYieldLevel() { return _yieldLevel; }
export function getCurrentDomain() { return _currentDomain; }

export function registerDefaultHotkeys({ onFreeze, onVision, onNewTab, onCloseTab }) {
  register('new_tab',   { key: 't', ctrl: true },  onNewTab,   { yieldInPartial: false });
  register('close_tab', { key: 'w', ctrl: true },  onCloseTab, { yieldInPartial: true  });
  register('freeze',    { key: 's', ctrl: true },  onFreeze,   { yieldInPartial: true  });

  register('vision_alt', { key: 'Alt', alt: false }, () => {
    _visionActive = true;
  }, { yieldInPartial: false });
}
