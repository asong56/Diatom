/**
 * diatom/src/features/tab-groups.js  — v0.9.6
 *
 * Tab Groups — Workspaces 2.0
 *
 * Inspired by Chrome's upcoming "Project" concept, which merges Tab Groups
 * and Workspaces into a single intent-based container. In Diatom, we keep
 * the branding as "Workspace" but elevate Groups as a first-class sub-unit
 * within each Workspace.
 *
 * Hierarchy:
 *   Workspace (max 8, persisted in SQLite)
 *   └── Group (0-n per workspace, named + colored, collapsible)
 *       └── Tab (n per group, or ungrouped at workspace root)
 *
 * Differences from Chrome Tab Groups:
 *   - Groups persist between sessions (stored in SQLite via cmd_tab_group_*)
 *   - Groups are tied to a Workspace — cross-workspace moves are supported
 *   - Collapsing a group puts all member tabs into shallow sleep
 *   - "Project mode": a group can be pinned to always occupy the Focus zone
 *     (61.8%) of the adaptive tab budget
 *   - No Chromium required — all state in Rust/SQLite
 *
 * IPC commands used:
 *   cmd_tab_group_create   { workspace_id, name, color, project_mode }
 *   cmd_tab_group_delete   { group_id }
 *   cmd_tab_group_rename   { group_id, name }
 *   cmd_tab_group_move_tab { tab_id, group_id | null }
 *   cmd_tab_groups_list    { workspace_id }
 *   cmd_tab_group_collapse { group_id, collapsed }
 */

'use strict';

import { invoke } from '../browser/ipc.js';
import { el, qs, escHtml, uid } from '../browser/utils.js';

// ── State ──────────────────────────────────────────────────────────────────────

/** @type {Map<string, TabGroup>}  groupId → group */
let _groups = new Map();
/** @type {Map<string, string>}   tabId   → groupId (null = ungrouped) */
let _tabGroupMap = new Map();
/** Currently active workspace id */
let _wsId = null;

// ── Types ──────────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} TabGroup
 * @property {string}   id
 * @property {string}   workspace_id
 * @property {string}   name
 * @property {string}   color   — hex or CSS color name
 * @property {boolean}  collapsed
 * @property {boolean}  project_mode  — if true, always in Focus zone
 * @property {string[]} tab_ids
 * @property {number}   created_at
 */

// ── Init ──────────────────────────────────────────────────────────────────────

export async function initTabGroups(workspaceId) {
  _wsId = workspaceId;
  await loadGroups(workspaceId);
  renderGroupHeaders();
}

async function loadGroups(wsId) {
  try {
    const groups = await invoke('cmd_tab_groups_list', { workspace_id: wsId });
    _groups.clear();
    _tabGroupMap.clear();
    for (const g of (groups ?? [])) {
      _groups.set(g.id, g);
      for (const tid of g.tab_ids) {
        _tabGroupMap.set(tid, g.id);
      }
    }
  } catch (e) {
    console.warn('[TabGroups] load failed:', e);
  }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Create a new group in the current workspace.
 * @param {string} name
 * @param {string} color   — e.g. '#60a5fa'
 * @param {boolean} projectMode
 */
export async function createGroup(name, color = '#60a5fa', projectMode = false) {
  try {
    const group = await invoke('cmd_tab_group_create', {
      workspace_id: _wsId,
      name,
      color,
      project_mode: projectMode,
    });
    _groups.set(group.id, group);
    renderGroupHeaders();
    return group;
  } catch (e) {
    console.error('[TabGroups] create failed:', e);
    return null;
  }
}

/**
 * Delete a group (its tabs become ungrouped).
 * @param {string} groupId
 */
export async function deleteGroup(groupId) {
  try {
    await invoke('cmd_tab_group_delete', { group_id: groupId });
    const group = _groups.get(groupId);
    if (group) {
      for (const tid of group.tab_ids) _tabGroupMap.delete(tid);
    }
    _groups.delete(groupId);
    renderGroupHeaders();
  } catch (e) {
    console.error('[TabGroups] delete failed:', e);
  }
}

/**
 * Move a tab into a group (or ungroup it with groupId=null).
 * @param {string} tabId
 * @param {string|null} groupId
 */
export async function moveTabToGroup(tabId, groupId) {
  try {
    await invoke('cmd_tab_group_move_tab', { tab_id: tabId, group_id: groupId });
    // Update local state
    const oldGroup = _tabGroupMap.get(tabId);
    if (oldGroup) {
      const g = _groups.get(oldGroup);
      if (g) g.tab_ids = g.tab_ids.filter(id => id !== tabId);
    }
    if (groupId) {
      _tabGroupMap.set(tabId, groupId);
      const g = _groups.get(groupId);
      if (g && !g.tab_ids.includes(tabId)) g.tab_ids.push(tabId);
    } else {
      _tabGroupMap.delete(tabId);
    }
    renderGroupHeaders();
  } catch (e) {
    console.error('[TabGroups] moveTab failed:', e);
  }
}

/**
 * Collapse or expand a group (collapses → shallow-sleeps all member tabs).
 * @param {string} groupId
 * @param {boolean} collapsed
 */
export async function setGroupCollapsed(groupId, collapsed) {
  try {
    await invoke('cmd_tab_group_collapse', { group_id: groupId, collapsed });
    const g = _groups.get(groupId);
    if (g) {
      g.collapsed = collapsed;
      // Sleep/wake tabs in bulk
      for (const tid of g.tab_ids) {
        if (collapsed) {
          invoke('cmd_tab_sleep', { tab_id: tid }).catch(() => {});
        } else {
          invoke('cmd_tab_wake',  { tab_id: tid }).catch(() => {});
        }
      }
    }
    renderGroupHeaders();
  } catch (e) {
    console.error('[TabGroups] collapse failed:', e);
  }
}

/**
 * Rename a group.
 * @param {string} groupId
 * @param {string} newName
 */
export async function renameGroup(groupId, newName) {
  try {
    await invoke('cmd_tab_group_rename', { group_id: groupId, name: newName });
    const g = _groups.get(groupId);
    if (g) g.name = newName;
    renderGroupHeaders();
  } catch (e) {
    console.error('[TabGroups] rename failed:', e);
  }
}

/** Return the group a given tab belongs to, or null. */
export function groupForTab(tabId) {
  const gid = _tabGroupMap.get(tabId);
  return gid ? (_groups.get(gid) ?? null) : null;
}

/** Return all groups for current workspace. */
export function allGroups() {
  return Array.from(_groups.values());
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/**
 * Inject group-header chips into the tab bar.
 * Called after any group state change and by the tabs render loop.
 */
export function renderGroupHeaders() {
  const bar = qs('#tab-bar');
  if (!bar) return;

  // Remove existing group headers
  bar.querySelectorAll('.tab-group-header').forEach(n => n.remove());

  // Add group header chips before the first tab in each group
  for (const group of _groups.values()) {
    if (!group.tab_ids.length) continue;

    const firstTabBtn = bar.querySelector(
      `.tab-btn[data-tab-id="${group.tab_ids[0]}"]`
    );
    if (!firstTabBtn) continue;

    const header = buildGroupHeader(group);
    bar.insertBefore(header, firstTabBtn);
  }
}

function buildGroupHeader(group) {
  const chip = el('div', `tab-group-header${group.project_mode ? ' project-mode' : ''}`);
  chip.dataset.groupId = group.id;
  chip.style.setProperty('--group-color', group.color);

  // Color dot
  const dot = el('span', 'group-dot');
  dot.style.background = group.color;
  chip.appendChild(dot);

  // Name (editable on dblclick)
  const nameEl = el('span', 'group-name');
  nameEl.textContent = group.name;
  nameEl.title = group.project_mode ? `${group.name} (Project Mode)` : group.name;
  nameEl.addEventListener('dblclick', () => startRenameGroup(group.id, nameEl));
  chip.appendChild(nameEl);

  // Collapse toggle
  const toggle = el('button', 'group-toggle');
  toggle.textContent = group.collapsed ? '▶' : '▾';
  toggle.title = group.collapsed ? 'Expand group' : 'Collapse group';
  toggle.setAttribute('aria-label', toggle.title);
  toggle.addEventListener('click', e => {
    e.stopPropagation();
    setGroupCollapsed(group.id, !group.collapsed);
  });
  chip.appendChild(toggle);

  // Project mode star
  if (group.project_mode) {
    const star = el('span', 'group-project-star');
    star.textContent = '★';
    star.title = 'Project Mode — always in Focus zone';
    chip.appendChild(star);
  }

  // Context menu on right-click
  chip.addEventListener('contextmenu', e => {
    e.preventDefault();
    showGroupContextMenu(group.id, e.clientX, e.clientY);
  });

  // Drag-over: allow dropping tabs into this group
  chip.addEventListener('dragover', e => {
    e.preventDefault();
    chip.classList.add('drag-over');
  });
  chip.addEventListener('dragleave', () => chip.classList.remove('drag-over'));
  chip.addEventListener('drop', e => {
    e.preventDefault();
    chip.classList.remove('drag-over');
    const tabId = e.dataTransfer?.getData('tab-id');
    if (tabId) moveTabToGroup(tabId, group.id);
  });

  return chip;
}

function startRenameGroup(groupId, nameEl) {
  const input = document.createElement('input');
  input.className = 'group-name-input';
  input.value = nameEl.textContent;
  input.style.cssText = 'border:none;background:transparent;font:inherit;color:inherit;width:8rem;outline:1px solid var(--c-accent);border-radius:.2rem;';
  nameEl.replaceWith(input);
  input.focus();
  input.select();
  const commit = () => {
    const newName = input.value.trim() || 'Group';
    renameGroup(groupId, newName).then(() => renderGroupHeaders());
  };
  input.addEventListener('blur', commit);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); commit(); }
    if (e.key === 'Escape') { renderGroupHeaders(); }
  });
}

function showGroupContextMenu(groupId, x, y) {
  // Remove any existing context menu
  document.getElementById('group-ctx-menu')?.remove();

  const menu = el('div', 'ctx-menu');
  menu.id = 'group-ctx-menu';
  menu.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:99999;`;

  const group = _groups.get(groupId);
  if (!group) return;

  const items = [
    {
      label: group.project_mode ? '★ Disable Project Mode' : '☆ Enable Project Mode',
      action: () => {
        invoke('cmd_tab_group_set_project_mode', {
          group_id: groupId,
          project_mode: !group.project_mode,
        }).then(() => loadGroups(_wsId).then(renderGroupHeaders));
      }
    },
    {
      label: `Rename "${group.name}"`,
      action: () => {
        const nameEl = document.querySelector(`.tab-group-header[data-group-id="${groupId}"] .group-name`);
        if (nameEl) startRenameGroup(groupId, nameEl);
      }
    },
    {
      label: 'Move all tabs to new workspace',
      action: async () => {
        const ws = await invoke('cmd_workspace_create', { name: group.name, color: group.color });
        for (const tid of group.tab_ids) {
          await invoke('cmd_tab_move_workspace', { tab_id: tid, workspace_id: ws.id }).catch(() => {});
        }
        await deleteGroup(groupId);
      }
    },
    { separator: true },
    {
      label: '🗑 Delete group (keep tabs)',
      action: () => deleteGroup(groupId),
      danger: true,
    },
  ];

  for (const item of items) {
    if (item.separator) {
      const sep = el('hr', 'ctx-sep');
      menu.appendChild(sep);
      continue;
    }
    const btn = el('button', `ctx-item${item.danger ? ' ctx-danger' : ''}`);
    btn.textContent = item.label;
    btn.addEventListener('click', () => { item.action(); menu.remove(); });
    menu.appendChild(btn);
  }

  document.body.appendChild(menu);
  // Close on outside click
  const dismiss = e => {
    if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click', dismiss); }
  };
  setTimeout(() => document.addEventListener('click', dismiss), 0);
}

// ── Quick-add group from omnibox ───────────────────────────────────────────────

/**
 * Create a group from the new-group button in the tab bar.
 * Prompts for a name inline.
 */
export function promptNewGroup() {
  const bar = qs('#tab-bar');
  if (!bar) return;

  const chip = el('div', 'tab-group-header tab-group-creating');
  const input = document.createElement('input');
  input.className = 'group-name-input';
  input.placeholder = 'Group name…';
  input.maxLength = 32;
  input.style.cssText = 'border:none;background:transparent;font:inherit;color:inherit;width:9rem;outline:none;';

  chip.appendChild(input);
  bar.appendChild(chip);
  input.focus();

  // Color picker (inline swatches)
  const COLORS = ['#60a5fa','#34d399','#fbbf24','#f87171','#a78bfa','#fb923c','#e879f9','#94a3b8'];
  let chosenColor = COLORS[Math.floor(Math.random() * COLORS.length)];
  const swatches = el('div', 'group-color-swatches');
  swatches.style.cssText = 'display:flex;gap:.25rem;padding:.25rem 0;';
  for (const c of COLORS) {
    const sw = el('button', 'color-swatch');
    sw.style.cssText = `width:1rem;height:1rem;border-radius:50%;background:${c};border:2px solid ${c === chosenColor ? '#fff' : 'transparent'};cursor:pointer;`;
    sw.addEventListener('click', () => {
      chosenColor = c;
      swatches.querySelectorAll('.color-swatch').forEach(s => {
        s.style.borderColor = s.style.background === c ? '#fff' : 'transparent';
      });
    });
    swatches.appendChild(sw);
  }
  chip.appendChild(swatches);

  const commit = async () => {
    const name = input.value.trim();
    chip.remove();
    if (name) {
      await createGroup(name, chosenColor, false);
    }
  };
  input.addEventListener('blur', commit);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); commit(); }
    if (e.key === 'Escape') { chip.remove(); }
  });
}

// ── CSS for group headers (injected once) ─────────────────────────────────────

(function injectGroupStyles() {
  if (document.getElementById('diatom-group-styles')) return;
  const style = document.createElement('style');
  style.id = 'diatom-group-styles';
  style.textContent = `
    .tab-group-header {
      display: inline-flex;
      align-items: center;
      gap: .3rem;
      padding: .15rem .5rem .15rem .35rem;
      margin-right: .15rem;
      border-radius: .3rem .3rem 0 0;
      background: color-mix(in srgb, var(--group-color, #60a5fa) 18%, var(--c-surface));
      border: 1px solid color-mix(in srgb, var(--group-color, #60a5fa) 35%, transparent);
      border-bottom: none;
      cursor: default;
      user-select: none;
      font-size: .7rem;
      font-weight: 600;
      color: var(--c-text-secondary);
      transition: background .15s;
      position: relative;
    }
    .tab-group-header:hover { background: color-mix(in srgb, var(--group-color, #60a5fa) 28%, var(--c-surface)); }
    .tab-group-header.project-mode {
      background: color-mix(in srgb, var(--group-color, #60a5fa) 22%, var(--c-surface));
      border-color: var(--group-color, #60a5fa);
    }
    .tab-group-header.drag-over {
      outline: 2px dashed var(--group-color, #60a5fa);
      outline-offset: 1px;
    }
    .group-dot {
      width: .55rem; height: .55rem;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .group-name {
      max-width: 8rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      cursor: text;
    }
    .group-toggle {
      background: none; border: none;
      color: var(--c-text-secondary);
      font-size: .65rem;
      padding: 0 .1rem;
      cursor: pointer;
      line-height: 1;
      opacity: .7;
    }
    .group-toggle:hover { opacity: 1; }
    .group-project-star { font-size: .7rem; opacity: .8; }
    .tab-group-creating { border: 1px dashed var(--c-border); }
    .ctx-menu {
      background: var(--c-surface);
      border: 1px solid var(--c-border);
      border-radius: .4rem;
      box-shadow: 0 8px 24px rgba(0,0,0,.18);
      padding: .25rem;
      min-width: 14rem;
    }
    .ctx-item {
      display: block; width: 100%;
      background: none; border: none;
      text-align: left; padding: .4rem .6rem;
      font-size: .78rem; color: var(--c-text);
      border-radius: .25rem; cursor: pointer;
    }
    .ctx-item:hover { background: var(--c-hover); }
    .ctx-item.ctx-danger { color: #f87171; }
    .ctx-sep { border: none; border-top: 1px solid var(--c-border); margin: .2rem 0; }
    .group-color-swatches button { border: none; cursor: pointer; }
  `;
  (document.head || document.documentElement).appendChild(style);
})();

// ── ⌘T Command Palette — Cross-workspace Tab & Group Search ──────────────────
//
// [FIX-TABGROUPS-01] Added Arc-style ⌘T command palette for cross-workspace
// tab search and navigation. Supports:
//   • Fuzzy search across ALL tabs in ALL workspaces (not just current)
//   • Group search: type ">" to filter by group name
//   • Workspace search: type "@" to filter by workspace
//   • Actions: switch to tab, move tab, close tab, create new group
//
// Keyboard: ⌘T (Mac) / Ctrl+T (Windows/Linux) to open
//           ↑↓ to navigate, Enter to select, Esc to dismiss

let _paletteEl = null;
let _paletteInput = null;
let _paletteList = null;
let _paletteItems = [];
let _paletteIdx = 0;
let _allTabsCache = [];

/** Fetch all tabs across all workspaces for cross-workspace search. */
async function loadAllTabsForPalette() {
  try {
    const { invoke } = window.__TAURI__.core;
    // Fetch all workspaces, then all groups+tabs within each
    const workspaces = await invoke('cmd_workspaces_list').catch(() => []);
    const tabs = [];
    for (const ws of workspaces) {
      const groups = await invoke('cmd_tab_groups_list', { workspace_id: ws.id }).catch(() => []);
      for (const grp of groups) {
        const grpTabs = await invoke('cmd_tabs_in_group', { group_id: grp.id }).catch(() => []);
        for (const t of grpTabs) {
          tabs.push({ ...t, _workspace: ws, _group: grp });
        }
      }
      // Also ungrouped tabs in workspace
      const ungrouped = await invoke('cmd_tabs_ungrouped', { workspace_id: ws.id }).catch(() => []);
      for (const t of ungrouped) {
        tabs.push({ ...t, _workspace: ws, _group: null });
      }
    }
    _allTabsCache = tabs;
  } catch (e) {
    console.warn('[diatom] palette: tab load failed', e);
  }
}

/** Fuzzy score: simple bigram overlap, case-insensitive. */
function fuzzyScore(query, target) {
  if (!query) return 1;
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  if (t.includes(q)) return 2;
  let hits = 0;
  for (let i = 0; i < q.length - 1; i++) {
    if (t.includes(q[i] + q[i + 1])) hits++;
  }
  return hits / Math.max(q.length - 1, 1);
}

/** Filter _allTabsCache by palette query. */
function filterPaletteItems(query) {
  const q = query.trim();
  let items = _allTabsCache;

  if (q.startsWith('>')) {
    // Group filter mode
    const gq = q.slice(1).trim().toLowerCase();
    items = _allTabsCache.filter(t =>
      t._group && t._group.name.toLowerCase().includes(gq)
    );
  } else if (q.startsWith('@')) {
    // Workspace filter mode
    const wq = q.slice(1).trim().toLowerCase();
    items = _allTabsCache.filter(t =>
      t._workspace.name.toLowerCase().includes(wq)
    );
  } else if (q) {
    // Fuzzy title + url search
    items = _allTabsCache
      .map(t => ({
        tab: t,
        score: Math.max(
          fuzzyScore(q, t.title || ''),
          fuzzyScore(q, t.url || '') * 0.8
        )
      }))
      .filter(x => x.score > 0.1)
      .sort((a, b) => b.score - a.score)
      .map(x => x.tab);
  }

  return items.slice(0, 12); // max 12 results
}

/** Render palette results list. */
function renderPaletteList(items) {
  _paletteItems = items;
  _paletteIdx = 0;
  _paletteList.innerHTML = '';

  if (!items.length) {
    const empty = document.createElement('div');
    empty.style.cssText = 'padding:.75rem;text-align:center;color:var(--c-text-secondary);font-size:.78rem;';
    empty.textContent = 'No matching tabs';
    _paletteList.appendChild(empty);
    return;
  }

  items.forEach((tab, i) => {
    const el = document.createElement('button');
    el.className = 'palette-item';
    el.dataset.idx = i;

    const favicon = document.createElement('img');
    favicon.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(tab.url || '')}&sz=16`;
    favicon.width = 14; favicon.height = 14;
    favicon.style.cssText = 'flex-shrink:0;border-radius:2px;opacity:.85;';
    favicon.onerror = () => { favicon.style.display = 'none'; };

    const info = document.createElement('div');
    info.style.cssText = 'flex:1;min-width:0;text-align:left;';

    const title = document.createElement('div');
    title.style.cssText = 'font-size:.8rem;font-weight:500;color:var(--c-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
    title.textContent = tab.title || tab.url || 'Untitled';

    const meta = document.createElement('div');
    meta.style.cssText = 'font-size:.68rem;color:var(--c-text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
    const wsPart = tab._workspace?.name || '';
    const grpPart = tab._group ? ` › ${tab._group.name}` : '';
    meta.textContent = `${wsPart}${grpPart}`;

    info.appendChild(title);
    info.appendChild(meta);
    el.appendChild(favicon);
    el.appendChild(info);

    if (i === 0) el.setAttribute('data-selected', 'true');
    el.addEventListener('click', () => selectPaletteItem(i));
    _paletteList.appendChild(el);
  });
}

/** Navigate palette selection. */
function movePaletteSelection(delta) {
  const items = _paletteList.querySelectorAll('.palette-item');
  if (!items.length) return;
  items[_paletteIdx]?.removeAttribute('data-selected');
  _paletteIdx = (_paletteIdx + delta + items.length) % items.length;
  const selected = items[_paletteIdx];
  selected?.setAttribute('data-selected', 'true');
  selected?.scrollIntoView({ block: 'nearest' });
}

/** Activate selected palette item. */
async function selectPaletteItem(idx) {
  const tab = _paletteItems[idx ?? _paletteIdx];
  if (!tab) return;
  closePalette();
  try {
    const { invoke } = window.__TAURI__.core;
    await invoke('cmd_tab_activate', { tab_id: tab.id, workspace_id: tab._workspace.id });
  } catch (e) {
    console.warn('[diatom] palette: activate failed', e);
  }
}

/** Open the command palette. */
export async function openCommandPalette() {
  if (_paletteEl) { _paletteInput?.focus(); return; }

  // Build overlay
  const overlay = document.createElement('div');
  overlay.id = '__diatom_palette_overlay';
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483646;
    background:rgba(0,0,0,.45);backdrop-filter:blur(2px);
    display:flex;align-items:flex-start;justify-content:center;
    padding-top:12vh;
  `;

  const panel = document.createElement('div');
  panel.style.cssText = `
    background:var(--c-surface);
    border:1px solid var(--c-border);
    border-radius:.7rem;
    box-shadow:0 24px 48px rgba(0,0,0,.35);
    width:min(600px, 92vw);
    overflow:hidden;
    display:flex;flex-direction:column;
  `;

  const inputWrap = document.createElement('div');
  inputWrap.style.cssText = 'display:flex;align-items:center;gap:.5rem;padding:.65rem .85rem;border-bottom:1px solid var(--c-border);';

  const searchIcon = document.createElement('span');
  searchIcon.textContent = '⌘';
  searchIcon.style.cssText = 'font-size:.9rem;color:var(--c-text-secondary);flex-shrink:0;';

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'Search tabs across all workspaces…  › group  @ workspace';
  input.style.cssText = `
    flex:1;background:none;border:none;outline:none;
    font-size:.88rem;color:var(--c-text);
    font-family:inherit;
  `;
  _paletteInput = input;

  const hint = document.createElement('span');
  hint.style.cssText = 'font-size:.68rem;color:var(--c-text-secondary);flex-shrink:0;';
  hint.textContent = 'Esc to close';

  inputWrap.appendChild(searchIcon);
  inputWrap.appendChild(input);
  inputWrap.appendChild(hint);

  const list = document.createElement('div');
  list.style.cssText = 'max-height:min(380px,55vh);overflow-y:auto;padding:.3rem;';
  _paletteList = list;

  panel.appendChild(inputWrap);
  panel.appendChild(list);
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  _paletteEl = overlay;

  // Inject palette item styles
  if (!document.getElementById('diatom-palette-styles')) {
    const s = document.createElement('style');
    s.id = 'diatom-palette-styles';
    s.textContent = `
      .palette-item {
        display:flex;align-items:center;gap:.55rem;
        width:100%;padding:.45rem .6rem;
        background:none;border:none;border-radius:.35rem;cursor:pointer;
        transition:background .1s;
      }
      .palette-item:hover,.palette-item[data-selected] {
        background:var(--c-hover);
      }
    `;
    document.head.appendChild(s);
  }

  // Load tabs and render initial list
  await loadAllTabsForPalette();
  renderPaletteList(filterPaletteItems(''));
  input.focus();

  input.addEventListener('input', () => {
    renderPaletteList(filterPaletteItems(input.value));
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown')  { e.preventDefault(); movePaletteSelection(+1); }
    if (e.key === 'ArrowUp')    { e.preventDefault(); movePaletteSelection(-1); }
    if (e.key === 'Enter')      { e.preventDefault(); selectPaletteItem(); }
    if (e.key === 'Escape')     { closePalette(); }
  });

  overlay.addEventListener('mousedown', e => {
    if (e.target === overlay) closePalette();
  });
}

/** Close the command palette. */
export function closePalette() {
  _paletteEl?.remove();
  _paletteEl = null;
  _paletteInput = null;
  _paletteList = null;
}

/** Register ⌘T / Ctrl+T global hotkey for the command palette. */
export function registerPaletteHotkey() {
  document.addEventListener('keydown', e => {
    const isMac = navigator.platform.toLowerCase().includes('mac');
    const trigger = isMac
      ? (e.metaKey && e.key === 't')
      : (e.ctrlKey && e.key === 't');
    if (trigger) {
      e.preventDefault();
      openCommandPalette();
    }
  }, { capture: true });
}
