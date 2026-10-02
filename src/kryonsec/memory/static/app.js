'use strict';
/* Kryonsec memory browser.
 *
 * Read-only: every request is a GET, and the server has no other route to
 * call. Nothing here writes, and nothing here reaches the network beyond
 * this origin (the page's CSP forbids it).
 *
 * Three habits matter throughout:
 *   - everything interpolated into HTML goes through esc(). Node labels are
 *     observations from tools — a page title, a banner — so they are
 *     attacker-influenced text, not trusted markup.
 *   - the canvas layout is hand-written. No graph library, no CDN.
 *   - colours are read from the stylesheet's own custom properties, so the
 *     canvas and the panels can never drift apart and dark mode is a
 *     re-read rather than a second palette.
 *
 * Node design: a node is a dot and a name. Nothing else is drawn on the
 * canvas — no cards, no boxes, no icons, no badges, no embedded metadata.
 * Everything known about a node lives in the inspector panel.
 */

(() => {

const $ = (id) => document.getElementById(id);

/* ---------------------------------------------------------------- helpers */

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

/* ------------------------------------------------------------- the palette */

/* Read straight off :root so there is exactly one definition of "the
 * Kryonsec purple". `readTheme()` re-runs on every theme flip. */
const theme = {
  bg: '#f5f5f0', fg: '#1a1a1a', border: '#3a3a3a',
  muted: '#626262', accent: '#a855f7',
};

function readTheme() {
  const cs = getComputedStyle(document.documentElement);
  for (const name of Object.keys(theme)) {
    const value = cs.getPropertyValue('--' + name).trim();
    if (value) theme[name] = value;
  }
}

function rgba(color, alpha) {
  const hex = String(color).trim().replace('#', '');
  const full = hex.length === 3 ? hex.split('').map((c) => c + c).join('') : hex;
  const n = parseInt(full, 16);
  if (!Number.isFinite(n) || full.length !== 6) return color;
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

/* ------------------------------------------------------------------ state */

const state = {
  engagements: [],
  storage: null,
  current: null,
  nodes: [],
  links: [],
  types: new Set(),
  statuses: new Set(),
  query: '',
  selection: null,
  hover: null,
  hoverEdge: null,
  camera: { x: 0, y: 0, k: 1 },
  alpha: 0,
  frame: null,
};

const canvas = $('graph');
const ctx = canvas.getContext('2d');

/* A node whose status is proposed/inferred is a hypothesis nobody has
 * confirmed, and it is drawn hollow. That is the only thing besides size
 * and colour that the canvas says about a node — everything else is in the
 * inspector. */
function isConfirmed(status) {
  return status !== 'proposed' && status !== 'inferred';
}

/* -------------------------------------------------------------------- api */

async function api(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  let body = null;
  try { body = await response.json(); } catch (err) { body = null; }
  if (!response.ok) {
    const message = body && body.error ? body.error.message : `HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.detail = body;
    throw error;
  }
  return body;
}

/* --------------------------------------------------------------- overlays */

function overlay(title, bodyHtml) {
  $('overlay-title').textContent = title;
  $('overlay-body').innerHTML = bodyHtml;
  $('overlay').classList.remove('hidden');
}
function hideOverlay() { $('overlay').classList.add('hidden'); }

function notice(text, warn) {
  const box = $('banner');
  if (!text) { box.classList.add('hidden'); return; }
  box.textContent = text;
  box.classList.toggle('info', !warn);
  box.classList.remove('hidden');
}

/* ------------------------------------------------------- engagement list */

const STATUS_PILL = {
  complete: 'pill-complete', halted: 'pill-halted',
  incomplete: 'pill-incomplete', failed: 'pill-failed',
};

function pill(status) {
  const value = status || 'unknown';
  return el('span', 'pill ' + (STATUS_PILL[value] || ''), value);
}

async function loadEngagements() {
  let payload;
  try {
    payload = await api('/api/engagements');
  } catch (err) {
    $('storage-text').textContent = 'unreachable';
    overlay('Cannot reach the Kryonsec memory server', esc(err.message));
    return;
  }
  state.storage = payload.storage;
  state.engagements = payload.engagements || [];

  $('storage-text').textContent = payload.storage.kind;

  if (!payload.storage.available) {
    overlay('No engagement memory yet', esc(payload.storage.detail) +
      '<br><br>Run an engagement, then reload this page:' +
      '<code>kryonsec purple --target example.com</code>');
  } else if (state.engagements.length === 0) {
    overlay('No engagements recorded',
      '<p>The engagement database is ready but empty.</p>');
  }

  renderEngagementList();
  renderOverview();
}

function renderEngagementList() {
  const host = $('engagements');
  host.innerHTML = '';
  $('engagement-count').textContent = state.engagements.length || '0';

  if (!state.engagements.length) {
    host.appendChild(el('p', 'muted', 'None recorded.'));
    return;
  }

  for (const item of state.engagements) {
    const button = el('button', 'engagement');
    button.type = 'button';
    if (state.current && state.current.meta.engagement_id === item.engagement_id) {
      button.setAttribute('aria-current', 'true');
    }

    const id = el('div', 'id');
    id.appendChild(el('span', null, item.engagement_id));
    id.appendChild(pill(item.status));
    button.appendChild(id);

    const facts = [];
    if (item.persisted) facts.push(`${item.nodes}n / ${item.edges}e`);
    else facts.push('no saved graph');
    if (item.target) facts.push(item.target);
    if (item.updated_at) facts.push(item.updated_at.slice(0, 19).replace('T', ' '));
    button.appendChild(el('div', 'meta', facts.join('  ·  ')));

    button.addEventListener('click', () => selectEngagement(item.engagement_id));
    host.appendChild(button);
  }
}

/* --------------------------------------------------------- overview panel */

/* Every value here is read from the payload the server just returned.
 * When nothing is loaded the cells say so rather than showing a zero. */
function renderOverview() {
  const grid = $('overview-grid');
  const note = $('overview-note');
  grid.innerHTML = '';

  const meta = state.current ? state.current.meta : null;

  const cell = (label, value, technical) => {
    const box = el('div');
    box.appendChild(el('span', null, label));
    box.appendChild(el('strong', technical ? 'tech' : null,
                       value == null || value === '' ? '—' : String(value)));
    grid.appendChild(box);
  };

  if (!meta) {
    cell('ENGAGEMENT', 'none selected', true);
    cell('TARGET', null);
    cell('STATUS', null);
    cell('NODES', null);
    cell('RELATIONSHIPS', null);
    cell('GRAPH SAVED', null);
    note.textContent = 'Pick an engagement on the left.';
    note.classList.remove('warn');
    $('inspector-title').textContent = 'ENGAGEMENT';
    return;
  }

  cell('ENGAGEMENT', meta.engagement_id, true);
  cell('TARGET', meta.target, true);
  cell('STATUS', meta.status);
  cell('NODES', state.nodes.length);
  cell('RELATIONSHIPS', state.links.length);
  cell('GRAPH SAVED', meta.persisted ? 'yes' : 'no');

  const bits = [];
  if (!meta.persisted) bits.push('this engagement has no saved graph');
  if (meta.persist_failed) bits.push('the last attempt to save its graph failed');
  if (meta.status === 'halted' && meta.halt_reason) bits.push('stopped: ' + meta.halt_reason);
  if (state.current.redactions) {
    bits.push(`${state.current.redactions} secret-shaped value(s) masked`);
  }
  if (bits.length) {
    note.textContent = bits.join(' — ');
    note.classList.add('warn');
  } else {
    note.textContent = 'Graph loaded from persisted memory.';
    note.classList.remove('warn');
  }
  $('inspector-title').textContent = 'ENGAGEMENT';
}

/* ------------------------------------------------------ engagement content */

async function selectEngagement(engagementId) {
  overlay('Loading…', '');
  try {
    state.current = await api('/api/engagements/' + encodeURIComponent(engagementId));
  } catch (err) {
    const detail = err.detail && err.detail.error ? err.detail.error.message : err.message;
    overlay('Could not load engagement ' + engagementId, esc(detail) +
      '<p>The engagement list on the left is still usable.</p>');
    return;
  }

  const payload = state.current;
  buildModel(payload.graph);
  buildFilters();
  setSelection(null);
  renderEngagementList();
  renderOverview();

  if (state.nodes.length === 0) {
    overlay('Empty engagement',
      '<p>This engagement is recorded, but its graph has no nodes — '
      + 'nothing was observed before it stopped.</p>');
  } else {
    hideOverlay();
  }

  const meta = payload.meta;
  const bits = [];
  if (meta.status === 'halted' && meta.halt_reason) bits.push('stopped: ' + meta.halt_reason);
  if (!meta.persisted) bits.push('no graph was ever saved for this engagement');
  if (bits.length) notice(bits.join(' — '), true);
  else notice('');

  document.title = `kryonsec — ${engagementId}`;
}

function buildModel(graph) {
  const nodes = graph.nodes.map((raw) => ({
    raw,
    id: raw.id,
    label: raw.label,
    type: raw.node_type,
    status: raw.status,
    x: 0, y: 0, vx: 0, vy: 0, r: 4, degree: 0,
  }));
  const byId = new Map(nodes.map((n) => [n.id, n]));

  const links = [];
  for (const raw of graph.edges) {
    const source = byId.get(raw.source_node_id);
    const target = byId.get(raw.target_node_id);
    if (!source || !target) continue;   // the server rejects these; be safe
    const link = { raw, source, target };
    links.push(link);
    source.degree += 1;
    target.degree += 1;
  }

  // The dot stays small — a hub is a slightly less small dot, nothing more.
  for (const node of nodes) {
    node.r = 3.4 + Math.min(3.2, Math.sqrt(node.degree) * 1.15);
  }

  // seed on a spiral so the first frames do not explode from one point
  const golden = Math.PI * (3 - Math.sqrt(5));
  nodes.forEach((node, i) => {
    const radius = 34 * Math.sqrt(i + 0.5);
    const angle = i * golden;
    node.x = Math.cos(angle) * radius;
    node.y = Math.sin(angle) * radius;
  });

  state.nodes = nodes;
  state.links = links;
  state.selection = null;
  state.hover = null;
  state.hoverEdge = null;
  state.alpha = 1;
  state.camera = { x: 0, y: 0, k: 1 };
  start();
}

/* ------------------------------------------------------------- simulation */

/* Run in world units, but pull a little harder and sit a little further
 * apart than the old layout: named dots need room for their names. */
const REPULSION = 6400;
const SPRING = 0.016;
const SPRING_LENGTH = 118;
const DAMPING = 0.82;

function tick() {
  const nodes = state.nodes;
  const links = state.links;
  const alpha = state.alpha;

  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 0.01) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 0.01; }
      const d = Math.sqrt(d2);
      const force = (REPULSION * alpha) / d2;
      const fx = (dx / d) * force;
      const fy = (dy / d) * force;
      a.vx -= fx; a.vy -= fy;
      b.vx += fx; b.vy += fy;
    }
  }

  for (const link of links) {
    const dx = link.target.x - link.source.x;
    const dy = link.target.y - link.source.y;
    const d = Math.max(0.01, Math.sqrt(dx * dx + dy * dy));
    const force = (d - SPRING_LENGTH) * SPRING * alpha;
    const fx = (dx / d) * force;
    const fy = (dy / d) * force;
    link.source.vx += fx; link.source.vy += fy;
    link.target.vx -= fx; link.target.vy -= fy;
  }

  let drift = 0;
  for (const node of nodes) {
    if (node.fixed) { node.vx = 0; node.vy = 0; continue; }
    // gravity toward the origin keeps disconnected clusters on screen
    node.vx -= node.x * 0.0016 * alpha;
    node.vy -= node.y * 0.0016 * alpha;
    node.vx *= DAMPING; node.vy *= DAMPING;
    node.x += node.vx; node.y += node.vy;
    drift += Math.abs(node.vx) + Math.abs(node.vy);
  }
  return drift / Math.max(1, nodes.length);
}

function start(alpha) {
  state.alpha = alpha === undefined ? 1 : alpha;
  if (state.frame) cancelAnimationFrame(state.frame);
  const step = () => {
    const drift = tick();
    state.alpha *= 0.985;
    draw();
    if (state.alpha > 0.02 && drift > 0.02) {
      state.frame = requestAnimationFrame(step);
    } else {
      state.frame = null;
      state.alpha = 0;
      fit();
      draw();
    }
  };
  state.frame = requestAnimationFrame(step);
}

function reheat(amount) {
  if (state.frame) {
    // already cooling — just put heat back, without restarting the decay
    state.alpha = Math.max(state.alpha, amount);
    return;
  }
  start(amount);
}

/* ------------------------------------------------------------------ view */

function sizeCanvas() {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.max(1, Math.round(rect.height * ratio));
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
}

function toScreen(wx, wy) {
  const cam = state.camera;
  return {
    x: (wx - cam.x) * cam.k + canvas.clientWidth / 2,
    y: (wy - cam.y) * cam.k + canvas.clientHeight / 2,
  };
}
function toWorld(sx, sy) {
  const cam = state.camera;
  return {
    x: (sx - canvas.clientWidth / 2) / cam.k + cam.x,
    y: (sy - canvas.clientHeight / 2) / cam.k + cam.y,
  };
}

function fit() {
  const nodes = state.nodes;
  if (!nodes.length) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const node of nodes) {
    minX = Math.min(minX, node.x); maxX = Math.max(maxX, node.x);
    minY = Math.min(minY, node.y); maxY = Math.max(maxY, node.y);
  }
  const width = Math.max(1, maxX - minX);
  const height = Math.max(1, maxY - minY);
  // room on the right for the labels, which extend past the last dot
  const pad = 150;
  const k = Math.min(
    (canvas.clientWidth - pad) / width,
    (canvas.clientHeight - pad) / height,
    2.2,
  );
  state.camera.k = Math.max(0.08, k);
  state.camera.x = (minX + maxX) / 2 + (pad / 4) / state.camera.k;
  state.camera.y = (minY + maxY) / 2;
}

function zoomAt(screenX, screenY, factor) {
  const before = toWorld(screenX, screenY);
  state.camera.k = Math.min(6, Math.max(0.05, state.camera.k * factor));
  const after = toWorld(screenX, screenY);
  state.camera.x += before.x - after.x;
  state.camera.y += before.y - after.y;
}

/* ---------------------------------------------------------------- filters */

function buildFilters() {
  const types = [...new Set(state.nodes.map((n) => n.type))].sort();
  const statuses = [...new Set(state.nodes.map((n) => n.status))].sort();

  // A new engagement resets the filters: carrying "hypothesis only" over to
  // an engagement that has none would show an empty canvas for no reason.
  state.types = new Set(types);
  state.statuses = new Set(statuses);
  state.query = '';
  $('search').value = '';

  renderChecks($('type-filters'), types, state.types);
  renderChecks($('status-filters'), statuses, state.statuses);
}

function renderChecks(host, values, active) {
  host.innerHTML = '';
  if (!values.length) { host.appendChild(el('span', 'muted', 'none')); return; }
  for (const value of values) {
    const label = el('label', 'check');
    label.dataset.on = String(active.has(value));
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = active.has(value);
    label.appendChild(input);
    label.appendChild(el('span', 'dot'));
    label.appendChild(el('span', null, value));
    input.addEventListener('change', () => {
      if (input.checked) active.add(value); else active.delete(value);
      label.dataset.on = String(input.checked);
      draw();
    });
    host.appendChild(label);
  }
}

function visible(node) {
  if (!state.types.has(node.type)) return false;
  if (!state.statuses.has(node.status)) return false;
  return true;
}

function matchesQuery(node) {
  if (!state.query) return true;
  return node.label.toLowerCase().includes(state.query)
      || node.type.toLowerCase().includes(state.query);
}

/* ------------------------------------------------------------------ draw */

/* Labels are set in VT323 at a fixed 16px — the readable technical face,
 * and a constant size so a name stays legible at any zoom. */
const LABEL_FONT = '16px "VT323", "Courier New", monospace';
const EDGE_LABEL_FONT = '15px "VT323", "Courier New", monospace';
const MAX_LABEL = 34;

function shortened(text) {
  return text.length > MAX_LABEL ? text.slice(0, MAX_LABEL - 1) + '…' : text;
}

/* Greedy screen-space label placement. Candidates are offered in priority
 * order (selection first, then hover, then neighbours, then search hits,
 * then everything else) so the labels that matter win the space; the rest
 * are simply not drawn. Under a very large graph that means some names are
 * only visible once you zoom or search — which is the trade the design
 * asks for: a legible graph, not every label at once. */
function labelPlacer() {
  const taken = [];
  return function place(x, y, width, height) {
    for (const box of taken) {
      if (x < box.x + box.w && x + width > box.x &&
          y < box.y + box.h && y + height > box.y) return false;
    }
    taken.push({ x, y, w: width, h: height });
    return true;
  };
}

function draw() {
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  ctx.clearRect(0, 0, width, height);

  if (!state.nodes.length) {
    $('hud-stats').textContent = '';
    return;
  }

  const cam = state.camera;
  const selected = state.selection && state.selection.kind === 'node'
    ? state.selection.item : null;
  const selectedEdge = state.selection && state.selection.kind === 'edge'
    ? state.selection.item : null;

  // screen positions, computed once
  for (const node of state.nodes) {
    const point = toScreen(node.x, node.y);
    node.sx = point.x;
    node.sy = point.y;
  }

  const related = new Set();
  if (selected) {
    for (const link of state.links) {
      if (link.source === selected) related.add(link.target);
      if (link.target === selected) related.add(link.source);
    }
  }

  const shown = state.nodes.filter(visible);
  const shownSet = new Set(shown);

  /* ---- edges: thin, quiet, and dimmed unless they touch the selection */
  ctx.lineCap = 'round';
  for (const link of state.links) {
    if (!shownSet.has(link.source) || !shownSet.has(link.target)) continue;
    const isSelectedEdge = link === selectedEdge || link === state.hoverEdge;
    const touches = selected && (link.source === selected || link.target === selected);

    if (isSelectedEdge) ctx.strokeStyle = theme.accent;
    else if (touches) ctx.strokeStyle = rgba(theme.accent, 0.55);
    else if (selected) ctx.strokeStyle = rgba(theme.border, 0.13);
    else ctx.strokeStyle = rgba(theme.border, 0.3);
    ctx.lineWidth = isSelectedEdge ? 1.7 : touches ? 1.3 : 0.9;

    ctx.beginPath();
    ctx.moveTo(link.source.sx, link.source.sy);
    ctx.lineTo(link.target.sx, link.target.sy);
    ctx.stroke();

    if (isSelectedEdge) {
      // direction, shown only where it is being asked about
      const dx = link.target.sx - link.source.sx;
      const dy = link.target.sy - link.source.sy;
      const d = Math.hypot(dx, dy) || 1;
      const tip = link.target.r + 3;
      const ax = link.target.sx - (dx / d) * tip;
      const ay = link.target.sy - (dy / d) * tip;
      const size = 7;
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - (dx / d) * size - (dy / d) * size * 0.45,
                 ay - (dy / d) * size + (dx / d) * size * 0.45);
      ctx.lineTo(ax - (dx / d) * size + (dy / d) * size * 0.45,
                 ay - (dy / d) * size - (dx / d) * size * 0.45);
      ctx.closePath();
      ctx.fillStyle = theme.accent;
      ctx.fill();
    }
  }

  /* ---- relationship names: only for the edge in hand */
  const labelEdge = selectedEdge || state.hoverEdge;
  if (labelEdge && shownSet.has(labelEdge.source) && shownSet.has(labelEdge.target)) {
    const mx = (labelEdge.source.sx + labelEdge.target.sx) / 2;
    const my = (labelEdge.source.sy + labelEdge.target.sy) / 2;
    ctx.font = EDGE_LABEL_FONT;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const text = shortened(labelEdge.raw.relationship || 'related');
    const metrics = ctx.measureText(text);
    ctx.fillStyle = theme.bg;
    ctx.fillRect(mx - metrics.width / 2 - 4, my - 8, metrics.width + 8, 16);
    ctx.fillStyle = theme.accent;
    ctx.fillText(text, mx, my);
  }

  /* ---- nodes: a small circular dot, and nothing else */
  for (const node of shown) {
    const isSelected = node === selected;
    const isNeighbour = related.has(node);
    const isHovered = node === state.hover;
    const dim = (state.query && !matchesQuery(node))
             || (selected && !isSelected && !isNeighbour);

    const radius = node.r + (isSelected ? 2.2 : isHovered ? 1.2 : 0);
    const highlighted = isSelected || isHovered;

    ctx.globalAlpha = dim ? 0.16 : (selected && !isSelected && !isNeighbour ? 0.3 : 1);

    ctx.beginPath();
    ctx.arc(node.sx, node.sy, radius, 0, Math.PI * 2);
    if (isConfirmed(node.status)) {
      ctx.fillStyle = highlighted ? theme.accent : theme.fg;
      ctx.fill();
    } else {
      // unconfirmed: hollow
      ctx.strokeStyle = highlighted ? theme.accent : theme.fg;
      ctx.lineWidth = 1.6;
      ctx.stroke();
    }

    // a search hit gets a ring, so a match is findable in a crowded view
    if (state.query && !dim && matchesQuery(node) && !highlighted) {
      ctx.beginPath();
      ctx.arc(node.sx, node.sy, radius + 4, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(theme.accent, 0.9);
      ctx.lineWidth = 1.2;
      ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;

  /* ---- names, placed around their dots, colliding labels dropped */
  const place = labelPlacer();
  ctx.font = LABEL_FONT;
  ctx.textBaseline = 'middle';

  const ordered = shown.slice().sort((a, b) => {
    const rank = (n) => (n === selected ? 0 : n === state.hover ? 1
      : related.has(n) ? 2 : (state.query && matchesQuery(n)) ? 3 : 4);
    return rank(a) - rank(b) || b.degree - a.degree;
  });

  for (const node of ordered) {
    const isSelected = node === selected;
    const isHovered = node === state.hover;
    const isNeighbour = related.has(node);
    const dim = (state.query && !matchesQuery(node))
             || (selected && !isSelected && !isNeighbour);
    const important = isSelected || isHovered || isNeighbour;

    // At a wide zoom the long tail of names is dropped rather than smeared.
    if (!important && cam.k < 0.55) continue;
    if (dim && !important) continue;

    const text = shortened(node.label);
    const metrics = ctx.measureText(text);
    const w = metrics.width;
    const gap = node.r + 6;
    const h = 16;

    // right of the dot first, then left, then below, then above
    const slots = [
      { x: node.sx + gap, y: node.sy - h / 2, align: 'left' },
      { x: node.sx - gap - w, y: node.sy - h / 2, align: 'left' },
      { x: node.sx - w / 2, y: node.sy + gap, align: 'left' },
      { x: node.sx - w / 2, y: node.sy - gap - h, align: 'left' },
    ];

    for (const slot of slots) {
      if (!place(slot.x, slot.y, w, h)) continue;
      ctx.globalAlpha = dim ? 0.3 : 1;
      ctx.textAlign = slot.align;
      ctx.fillStyle = isSelected || isHovered ? theme.accent : theme.fg;
      ctx.fillText(text, slot.x, slot.y + h / 2);
      ctx.globalAlpha = 1;
      break;
    }
  }

  /* ---- hud */
  const visibleLinks = state.links.filter(
    (l) => shownSet.has(l.source) && shownSet.has(l.target)).length;
  $('hud-stats').textContent =
    `${shown.length}/${state.nodes.length} nodes · ${visibleLinks}/${state.links.length} edges · ${Math.round(cam.k * 100)}%`;

  const queryHits = state.query
    ? state.nodes.filter((n) => visible(n) && matchesQuery(n)).length : null;
  $('search-count').textContent = queryHits === null ? '' : `${queryHits} match`;
}

/* ------------------------------------------------------------ hit testing */

function pick(screenX, screenY) {
  for (let i = state.nodes.length - 1; i >= 0; i--) {
    const node = state.nodes[i];
    if (!visible(node)) continue;
    const reach = Math.max(node.r + 5, 9);
    if (Math.hypot(node.sx - screenX, node.sy - screenY) <= reach) {
      return { kind: 'node', item: node };
    }
  }

  let best = null;
  let bestDistance = 7;
  for (const link of state.links) {
    if (!visible(link.source) || !visible(link.target)) continue;
    const distance = pointSegment(
      { x: screenX, y: screenY },
      { x: link.source.sx, y: link.source.sy },
      { x: link.target.sx, y: link.target.sy });
    if (distance < bestDistance) { bestDistance = distance; best = link; }
  }
  return best ? { kind: 'edge', item: best } : null;
}

function pointSegment(p, a, b) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const lengthSq = dx * dx + dy * dy;
  if (lengthSq === 0) return Math.hypot(p.x - a.x, p.y - a.y);
  let t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / lengthSq;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

/* ----------------------------------------------------------- interaction */

let drag = null;

canvas.addEventListener('mousedown', (event) => {
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  const hit = pick(x, y);
  if (hit && hit.kind === 'node') {
    drag = { kind: 'node', node: hit.item, moved: false, x, y };
    hit.item.fixed = true;
  } else {
    drag = { kind: 'pan', x, y, camX: state.camera.x, camY: state.camera.y, moved: false };
  }
  canvas.classList.add('dragging');
});

canvas.addEventListener('mousemove', (event) => {
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;

  if (drag) {
    drag.moved = true;
    if (drag.kind === 'node') {
      const world = toWorld(x, y);
      drag.node.x = world.x; drag.node.y = world.y;
      reheat(0.55);
    } else {
      state.camera.x = drag.camX - (x - drag.x) / state.camera.k;
      state.camera.y = drag.camY - (y - drag.y) / state.camera.k;
      draw();
    }
    return;
  }

  const hit = pick(x, y);
  const hovered = hit && hit.kind === 'node' ? hit.item : null;
  const hoveredEdge = hit && hit.kind === 'edge' ? hit.item : null;
  if (hovered !== state.hover || hoveredEdge !== state.hoverEdge) {
    state.hover = hovered;
    state.hoverEdge = hoveredEdge;
    canvas.style.cursor = hit ? 'pointer' : 'grab';
    draw();
  }
});

function endDrag(event) {
  if (!drag) return;
  canvas.classList.remove('dragging');
  if (drag.kind === 'node') drag.node.fixed = false;
  const wasClick = !drag.moved;
  drag = null;
  if (wasClick) {
    const rect = canvas.getBoundingClientRect();
    const hit = pick(event.clientX - rect.left, event.clientY - rect.top);
    setSelection(hit);
  }
}
canvas.addEventListener('mouseup', endDrag);
canvas.addEventListener('mouseleave', (event) => {
  if (drag) endDrag(event);
  state.hover = null;
  state.hoverEdge = null;
  draw();
});

canvas.addEventListener('wheel', (event) => {
  event.preventDefault();
  const rect = canvas.getBoundingClientRect();
  zoomAt(event.clientX - rect.left, event.clientY - rect.top,
         event.deltaY < 0 ? 1.12 : 1 / 1.12);
  draw();
}, { passive: false });

canvas.addEventListener('dblclick', (event) => {
  const rect = canvas.getBoundingClientRect();
  const hit = pick(event.clientX - rect.left, event.clientY - rect.top);
  if (hit) centerOn(hit.kind === 'node' ? hit.item : hit.item.source);
});

function centerOn(node) {
  state.camera.x = node.x;
  state.camera.y = node.y;
  state.camera.k = Math.max(state.camera.k, 1.1);
  draw();
}

/* ------------------------------------------------------------ detail view */

function setSelection(hit) {
  state.selection = hit;
  renderDetail();
  draw();
}

function renderDetail() {
  const body = $('detail');
  body.innerHTML = '';
  $('detail-head').textContent = 'INSPECTOR';

  if (!state.selection) {
    body.appendChild(el('p', 'muted',
      'Select a dot or a relationship line. Nothing here is editable — '
      + 'the browser only reads persisted memory.'));
    return;
  }
  if (state.selection.kind === 'node') renderNodeDetail(body, state.selection.item);
  else renderEdgeDetail(body, state.selection.item);
}

function section(parent, title) {
  const box = el('div', 'section');
  box.appendChild(el('h4', null, title));
  parent.appendChild(box);
  return box;
}

function kv(parent, pairs) {
  const table = el('table', 'kv');
  for (const [key, value] of pairs) {
    const row = el('tr');
    row.appendChild(el('td', 'k', key));
    row.appendChild(el('td', null, value == null || value === '' ? '—' : String(value)));
    table.appendChild(row);
  }
  parent.appendChild(table);
  return table;
}

// JSON view with syntax colouring. Every piece of data goes through esc().
function jsonHtml(value) {
  if (value === null) return '<span class="n">null</span>';
  if (typeof value === 'number') return `<span class="n">${esc(value)}</span>`;
  if (typeof value === 'boolean') return `<span class="n">${esc(value)}</span>`;
  if (typeof value === 'string') return `<span class="s">"${esc(value)}"</span>`;
  if (Array.isArray(value)) {
    if (!value.length) return '[]';
    return '[\n' + value.map((v) => '  ' + jsonHtml(v)).join(',\n') + '\n]';
  }
  const keys = Object.keys(value);
  if (!keys.length) return '{}';
  return '{\n' + keys.map((k) =>
    `  <span class="k">${esc(k)}</span>: ${jsonHtml(value[k])}`).join(',\n') + '\n}';
}

/* the landing page's .terminal block: near-black panel, readable technical
 * text — which is the right home for JSON, URLs and raw evidence */
function jsonBlock(parent, title, value) {
  const box = el('div', 'terminal');
  const head = el('div', 'terminal-head');
  head.appendChild(el('span', null, title));
  box.appendChild(head);
  const pre = el('pre');
  const empty = value == null
    || (typeof value === 'object' && !Array.isArray(value) && !Object.keys(value).length);
  pre.innerHTML = empty ? '<span class="empty">none recorded</span>' : jsonHtml(value);
  box.appendChild(pre);
  parent.appendChild(box);
  return box;
}

function provenanceRows(raw) {
  const provenance = raw.provenance || {};
  const entries = Object.entries(provenance);
  if (!entries.length) return [['recorded', 'nothing']];
  return entries.map(([key, value]) => [key, typeof value === 'object' ? JSON.stringify(value) : value]);
}

function renderNodeDetail(body, node) {
  const raw = node.raw;
  $('detail-head').textContent = 'NODE';

  body.appendChild(el('div', 'detail-title', raw.label));

  const badges = el('div', 'badges');
  badges.appendChild(el('span', 'pill', raw.node_type));
  badges.appendChild(el('span', 'pill', raw.status));
  body.appendChild(badges);

  kv(section(body, 'IDENTITY'), [
    ['id', raw.id],
    ['engagement', raw.engagement_id],
    ['canonical key', raw.canonical_key],
    ['created', raw.created_at],
    ['size', raw.size_bytes + ' B'],
  ]);

  kv(section(body, 'PROVENANCE'), provenanceRows(raw));

  jsonBlock(body, 'properties.json', raw.properties || {});

  const outgoing = state.links.filter((l) => l.source === node);
  const incoming = state.links.filter((l) => l.target === node);

  const relBox = section(body, `RELATIONSHIPS (${outgoing.length + incoming.length})`);
  for (const link of outgoing) relBox.appendChild(relRow(link, 'out', link.target));
  for (const link of incoming) relBox.appendChild(relRow(link, 'in', link.source));
  if (!outgoing.length && !incoming.length) {
    relBox.appendChild(el('p', 'muted', 'No recorded relationships.'));
  }
}

function renderEdgeDetail(body, link) {
  const raw = link.raw;
  $('detail-head').textContent = 'RELATIONSHIP';

  body.appendChild(el('div', 'detail-title', raw.relationship));

  const badges = el('div', 'badges');
  badges.appendChild(el('span', 'pill', raw.status));
  body.appendChild(badges);

  kv(section(body, 'RELATIONSHIP'), [
    ['from', `${link.source.label} (${link.source.type})`],
    ['to', `${link.target.label} (${link.target.type})`],
    ['id', raw.id],
    ['created', raw.created_at],
    ['size', raw.size_bytes + ' B'],
  ]);

  kv(section(body, 'PROVENANCE'), provenanceRows(raw));

  jsonBlock(body, 'properties.json', raw.properties || {});

  const navBox = section(body, 'NAVIGATE');
  navBox.appendChild(relRow(link, 'out', link.source, 'open source'));
  navBox.appendChild(relRow(link, 'in', link.target, 'open target'));
}

function relRow(link, direction, other, verb) {
  const row = el('button', 'rel');
  row.type = 'button';
  row.appendChild(el('span', 'dir', direction === 'in' ? '←' : '→'));
  row.appendChild(el('span', 'name', verb || link.raw.relationship));
  row.appendChild(el('span', 'other', other.label));
  row.addEventListener('click', () => {
    setSelection({ kind: 'node', item: other });
    centerOn(other);
  });
  return row;
}

/* ------------------------------------------------------------------ theme */

/* Exactly the landing page's toggle: same storage key, same aria wiring,
 * same ◐/◑ pair, same theme-color meta. The canvas re-reads the palette
 * afterwards so it flips with everything else. */
function applyTheme(mode) {
  const dark = mode === 'dark';
  document.documentElement.removeAttribute('data-theme');
  if (dark) document.documentElement.dataset.theme = 'dark';

  const toggle = $('theme-toggle');
  toggle.setAttribute('aria-pressed', String(dark));
  toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
  $('theme-label').textContent = dark ? 'LIGHT MODE' : 'DARK MODE';
  $('theme-icon').textContent = dark ? '◑' : '◐';
  $('theme-color').content = dark ? '#111112' : '#f5f5f0';

  readTheme();
  draw();
}

readTheme();
applyTheme(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');

$('theme-toggle').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('kryonsec-theme', next); } catch (_) {}
});

/* The legend describes the encoding, not the data — it never changes, and it
 * deliberately carries no per-type colours, because the graph has none. */
function renderLegend() {
  const host = $('legend');
  host.innerHTML = '';
  const item = (dotStyle, label) => {
    const span = el('span');
    const dot = el('i');
    Object.assign(dot.style, dotStyle);
    span.appendChild(dot);
    span.appendChild(el('span', null, label));
    host.appendChild(span);
  };
  item({ background: 'var(--fg)', borderColor: 'var(--fg)' }, 'confirmed');
  item({ background: 'transparent', borderColor: 'var(--fg)' }, 'proposed');
  item({ background: 'var(--accent)', borderColor: 'var(--accent)' }, 'selected');
}

/* ------------------------------------------------------------------ boot */

$('search').addEventListener('input', (event) => {
  state.query = event.target.value.trim().toLowerCase();
  draw();
});

$('clear-filters').addEventListener('click', () => {
  state.query = '';
  $('search').value = '';
  for (const node of state.nodes) { state.types.add(node.type); state.statuses.add(node.status); }
  buildFilters();
  draw();
});

for (const button of document.querySelectorAll('.hud [data-action]')) {
  button.addEventListener('click', () => {
    const action = button.dataset.action;
    if (action === 'fit') { fit(); draw(); }
    if (action === 'relayout') start();
  });
}

window.addEventListener('resize', () => { sizeCanvas(); draw(); });

/* The graph is a view of one engagement; a query string cannot conjure one
 * up, and the server never accepts a path from here it has not validated. */
sizeCanvas();
renderLegend();
loadEngagements();

})();
