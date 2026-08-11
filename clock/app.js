'use strict';

/* =========================================================================
   LED Clock — digital clock + world clocks + month calendar.
   No dependencies, no build step. State lives in localStorage.
   ========================================================================= */

const KEY = 'ledclock.v1';

const DEFAULT_CITIES = [
  { tz: 'Europe/London',       label: 'London'   },
  { tz: 'America/New_York',    label: 'New York' },
  { tz: 'America/Los_Angeles', label: 'Seattle'  },
  { tz: 'America/Chicago',     label: 'Austin'   },
  { tz: 'Asia/Shanghai',       label: 'Beijing'  },
  { tz: 'Asia/Kolkata',        label: 'Mumbai'   }
];

const DEFAULTS = {
  theme: 'green',
  hour12: true,
  seconds: false,
  ghost: false,     // faintly show unlit segments, like a real LED panel
  weekStart: 0,     // 0 = Sunday, 1 = Monday
  wake: false,
  cities: DEFAULT_CITIES
};

const clone = (o) => JSON.parse(JSON.stringify(o));

let S = (() => {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? Object.assign(clone(DEFAULTS), JSON.parse(raw)) : clone(DEFAULTS);
  } catch { return clone(DEFAULTS); }
})();

const save = () => { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch {} };

/* ---------------------------------------------------------------- elements */

const $ = (id) => document.getElementById(id);
const $time = $('time'), $srTime = $('srTime'), $dateline = $('dateline');
const $world = $('world'), $grid = $('grid'), $monthNum = $('monthNum');
const $sheet = $('sheet'), $scrim = $('scrim');
const $sheetTitle = $('sheetTitle'), $sheetBody = $('sheetBody');

/* ------------------------------------------------------------ time helpers */

const LOCAL_TZ = Intl.DateTimeFormat().resolvedOptions().timeZone;
const WD = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];

const _fmts = new Map();
function fmtFor(tz) {
  let f = _fmts.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, hourCycle: 'h23', weekday: 'short',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    _fmts.set(tz, f);
  }
  return f;
}

/** Wall-clock fields for `date` as seen in `tz`. */
function zoned(date, tz) {
  const o = {};
  for (const p of fmtFor(tz).formatToParts(date)) o[p.type] = p.value;
  return {
    y: +o.year, m: +o.month, d: +o.day,
    H: +o.hour % 24, M: +o.minute, S: +o.second,
    wd: String(o.weekday).toUpperCase()
  };
}

/** UTC offset of `tz` at `date`, in minutes. */
function offsetMin(date, tz) {
  const p = zoned(date, tz);
  return Math.round((Date.UTC(p.y, p.m - 1, p.d, p.H, p.M, p.S) - date.getTime()) / 60000);
}

/** "+5", "-3", "+9.5" — half-hour and 45-minute zones included. */
function fmtOffset(mins) {
  const h = Math.abs(mins) / 60;
  return (mins < 0 ? '-' : '+') + (Number.isInteger(h) ? h : +h.toFixed(2));
}

function clockStr(p) {
  let h = p.H, mer = '';
  if (S.hour12) { mer = h >= 12 ? ' PM' : ' AM'; h = h % 12 || 12; }
  const hh = S.hour12 ? String(h) : String(h).padStart(2, '0');
  const ss = S.seconds ? ':' + String(p.S).padStart(2, '0') : '';
  return `${hh}:${String(p.M).padStart(2, '0')}${ss}${mer}`;
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* -------------------------------------------------------- seven-segment SVG */

const SEGMENTS = {
  a: '17,2 43,2 48,7 43,12 17,12 12,7',
  b: '45,14 50,9 55,14 55,46 50,51 45,46',
  c: '45,60 50,55 55,60 55,92 50,97 45,92',
  d: '17,94 43,94 48,99 43,104 17,104 12,99',
  e: '5,60 10,55 15,60 15,92 10,97 5,92',
  f: '5,14 10,9 15,14 15,46 10,51 5,46',
  g: '17,48 43,48 48,53 43,58 17,58 12,53'
};

const LIT = {
  '0': 'abcdef', '1': 'bc',    '2': 'abged',  '3': 'abgcd', '4': 'fgbc',
  '5': 'afgcd',  '6': 'afgecd', '7': 'abc',   '8': 'abcdefg', '9': 'abcdfg'
};

function digitSVG(ch) {
  const on = LIT[ch] || '';
  let out = '<svg viewBox="0 0 60 106">';
  for (const k of 'abcdefg') {
    out += `<polygon class="${on.includes(k) ? 'on' : 'off'}" points="${SEGMENTS[k]}"/>`;
  }
  return out + '</svg>';
}

const colonSVG = () =>
  '<svg class="colon" viewBox="0 0 20 106">' +
  '<circle class="on" cx="10" cy="36" r="5.5"/>' +
  '<circle class="on" cx="10" cy="72" r="5.5"/></svg>';

/* -------------------------------------------------------------- rendering */

let view = null;          // {y, m} when browsing another month; null = follow today
let lastLocal = null;
let lastTimeKey = '', lastDayKey = '', lastMinKey = '';

function renderClock(p) {
  let h = p.H, mer = '';
  if (S.hour12) { mer = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12; }
  const hh = S.hour12 ? String(h) : String(h).padStart(2, '0');
  const mm = String(p.M).padStart(2, '0');
  const ss = String(p.S).padStart(2, '0');

  const key = [hh, mm, S.seconds ? ss : '', mer].join('|');
  if (key !== lastTimeKey) {
    let html = '';
    for (const ch of hh) html += digitSVG(ch);
    html += colonSVG();
    for (const ch of mm) html += digitSVG(ch);
    if (S.seconds) {
      html += colonSVG();
      for (const ch of ss) html += digitSVG(ch);
    }
    if (mer) html += `<span class="mer">${mer}</span>`;
    $time.innerHTML = html;
    lastTimeKey = key;
  }
  // colon blinks once per second, like the reference display
  const hide = p.S % 2 === 1;
  for (const c of $time.querySelectorAll('.colon')) c.classList.toggle('hide', hide);
  $srTime.textContent = clockStr(p);
}

function renderDate(p) {
  $dateline.textContent = `${p.y}. ${p.m}. ${p.d} ${p.wd}`;
}

function renderWorld(now, local) {
  if (!S.cities.length) {
    $world.innerHTML = '<div class="empty">No cities yet — tap the globe below.</div>';
    return;
  }
  const base = offsetMin(now, LOCAL_TZ);
  $world.innerHTML = S.cities.map((c) => {
    let p;
    try { p = zoned(now, c.tz); }
    catch { return `<div class="row">${esc(c.label)}: <span class="meta">unknown zone</span></div>`; }

    const off = fmtOffset(offsetMin(now, c.tz) - base);
    return `<div class="row">${esc(c.label)}: ${clockStr(p)} <span class="meta">(${p.wd} ${off})</span></div>`;
  }).join('');
}

function renderCal(local) {
  const y = view ? view.y : local.y;
  const m = view ? view.m : local.m;

  $monthNum.textContent = y === local.y ? String(m) : `${m} '${String(y).slice(2)}`;

  const startDow = new Date(Date.UTC(y, m - 1, 1)).getUTCDay();
  const daysIn = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const prevDaysIn = new Date(Date.UTC(y, m - 1, 0)).getUTCDate();

  const lead = (startDow - S.weekStart + 7) % 7;
  const trail = (7 - ((lead + daysIn) % 7)) % 7;   // just enough to finish the last week

  let html = '';
  for (let i = 0; i < 7; i++) html += `<div class="wd">${WD[(S.weekStart + i) % 7]}</div>`;

  // tail of the previous month
  for (let i = lead; i > 0; i--) html += `<div class="day other">${prevDaysIn - i + 1}</div>`;

  for (let d = 1; d <= daysIn; d++) {
    const today = y === local.y && m === local.m && d === local.d;
    html += `<div class="day${today ? ' today' : ''}"${today ? ' aria-current="date"' : ''}>${d}</div>`;
  }

  // head of the next month
  for (let d = 1; d <= trail; d++) html += `<div class="day other">${d}</div>`;

  $grid.innerHTML = html;
}

function applyChrome() {
  document.documentElement.dataset.theme = S.theme;
  document.documentElement.dataset.ghost = S.ghost ? 'on' : 'off';
}

/** Redraw everything immediately after a settings change. */
function refreshAll() {
  applyChrome();
  lastTimeKey = lastDayKey = lastMinKey = '';
  if (!lastLocal) return;
  renderClock(lastLocal);
  renderDate(lastLocal);
  renderWorld(new Date(), lastLocal);
  renderCal(lastLocal);
}

/* ------------------------------------------------------------------- tick */

function tick() {
  const now = new Date();
  const local = zoned(now, LOCAL_TZ);
  lastLocal = local;

  renderClock(local);

  const dayKey = `${local.y}-${local.m}-${local.d}`;
  if (dayKey !== lastDayKey) {
    lastDayKey = dayKey;
    renderDate(local);
    renderCal(local);
  }

  const minKey = `${dayKey} ${local.H}:${local.M}`;
  if (minKey !== lastMinKey) {
    lastMinKey = minKey;
    renderWorld(now, local);
  }

  setTimeout(tick, 1000 - (Date.now() % 1000) + 15);
}

/* ------------------------------------------------------------ month nav */

function shiftMonth(n) {
  const base = view || { y: lastLocal.y, m: lastLocal.m };
  let y = base.y, m = base.m + n;
  while (m > 12) { m -= 12; y++; }
  while (m < 1)  { m += 12; y--; }
  view = { y, m };
  renderCal(lastLocal);
}

$('prevMonth').onclick = () => shiftMonth(-1);
$('nextMonth').onclick = () => shiftMonth(1);
$monthNum.onclick = () => { view = null; renderCal(lastLocal); };

/* ---------------------------------------------------------------- sheets */

function openSheet(title, build) {
  $sheetTitle.textContent = title;
  $sheetBody.innerHTML = '';
  build($sheetBody);
  $sheet.hidden = false;
  $scrim.hidden = false;
}

function closeSheet() {
  $sheet.hidden = true;
  $scrim.hidden = true;
}

$('sheetClose').onclick = closeSheet;
$scrim.onclick = closeSheet;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSheet(); });

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function optRow(labelText, control) {
  const row = el('div', 'opt');
  row.appendChild(el('label', null, labelText));
  row.appendChild(control);
  return row;
}

function segControl(options, current, onPick) {
  const wrap = el('div', 'seg');
  options.forEach(([label, val]) => {
    const b = el('button', null, label);
    b.setAttribute('aria-pressed', String(val === current));
    b.onclick = () => {
      onPick(val); save(); refreshAll();
      [...wrap.children].forEach((c, i) =>
        c.setAttribute('aria-pressed', String(options[i][1] === val)));
    };
    wrap.appendChild(b);
  });
  return wrap;
}

/* --- theme --- */

const THEMES = [
  ['green', '#33ff66'], ['amber', '#ffb524'], ['red', '#ff4444'],
  ['cyan', '#33e5ff'], ['violet', '#b98cff'], ['white', '#e8e8e8']
];

$('btnTheme').onclick = () => openSheet('Theme', (body) => {
  const wrap = el('div', 'swatches');
  THEMES.forEach(([name, colour]) => {
    const b = el('button', 'swatch');
    b.title = name;
    b.setAttribute('aria-label', name);
    b.setAttribute('aria-pressed', String(S.theme === name));
    const dot = el('i');
    dot.style.background = colour;
    dot.style.boxShadow = `0 0 12px ${colour}`;
    b.appendChild(dot);
    b.onclick = () => {
      S.theme = name; save(); applyChrome();
      [...wrap.children].forEach((c) =>
        c.setAttribute('aria-pressed', String(c.title === name)));
    };
    wrap.appendChild(b);
  });
  body.appendChild(wrap);
});

/* --- settings --- */

$('btnSettings').onclick = () => openSheet('Settings', (body) => {
  body.append(
    optRow('Clock', segControl([['12 h', true], ['24 h', false]], S.hour12,
      (v) => { S.hour12 = v; })),
    optRow('Seconds', segControl([['Off', false], ['On', true]], S.seconds,
      (v) => { S.seconds = v; })),
    optRow('Ghost segments', segControl([['Off', false], ['On', true]], S.ghost,
      (v) => { S.ghost = v; })),
    optRow('Week starts', segControl([['Sun', 0], ['Mon', 1]], S.weekStart,
      (v) => { S.weekStart = v; })),
    optRow('Keep screen awake', segControl([['Off', false], ['On', true]], S.wake,
      (v) => { S.wake = v; applyWake(); }))
  );
  body.appendChild(el('p', 'hint', `Local time zone: ${LOCAL_TZ}`));
});

/* --- wake lock --- */

let wakeLock = null;
async function applyWake() {
  try {
    if (S.wake && 'wakeLock' in navigator) {
      if (!wakeLock) {
        wakeLock = await navigator.wakeLock.request('screen');
        wakeLock.addEventListener('release', () => { wakeLock = null; });
      }
    } else if (wakeLock) {
      await wakeLock.release();
      wakeLock = null;
    }
  } catch { /* denied or unsupported — not worth surfacing */ }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && S.wake) applyWake();
});

/* --- cities --- */

const FALLBACK_ZONES = [
  'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Lagos', 'Africa/Nairobi',
  'America/Anchorage', 'America/Argentina/Buenos_Aires', 'America/Bogota',
  'America/Chicago', 'America/Denver', 'America/Halifax', 'America/Lima',
  'America/Los_Angeles', 'America/Mexico_City', 'America/New_York',
  'America/Phoenix', 'America/Sao_Paulo', 'America/Toronto', 'America/Vancouver',
  'Asia/Bangkok', 'Asia/Dubai', 'Asia/Ho_Chi_Minh', 'Asia/Hong_Kong',
  'Asia/Jakarta', 'Asia/Jerusalem', 'Asia/Kabul', 'Asia/Karachi',
  'Asia/Kathmandu', 'Asia/Kolkata', 'Asia/Kuala_Lumpur', 'Asia/Manila',
  'Asia/Riyadh', 'Asia/Seoul', 'Asia/Shanghai', 'Asia/Singapore',
  'Asia/Taipei', 'Asia/Tehran', 'Asia/Tokyo', 'Australia/Adelaide',
  'Australia/Brisbane', 'Australia/Melbourne', 'Australia/Perth',
  'Australia/Sydney', 'Europe/Amsterdam', 'Europe/Athens', 'Europe/Berlin',
  'Europe/Brussels', 'Europe/Bucharest', 'Europe/Copenhagen', 'Europe/Dublin',
  'Europe/Helsinki', 'Europe/Istanbul', 'Europe/Lisbon', 'Europe/London',
  'Europe/Madrid', 'Europe/Moscow', 'Europe/Oslo', 'Europe/Paris',
  'Europe/Prague', 'Europe/Rome', 'Europe/Stockholm', 'Europe/Vienna',
  'Europe/Warsaw', 'Europe/Zurich', 'Pacific/Auckland', 'Pacific/Fiji',
  'Pacific/Honolulu', 'UTC'
];

function allZones() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const z = Intl.supportedValuesOf('timeZone');
      if (z && z.length) return z;
    }
  } catch { /* fall through */ }
  return FALLBACK_ZONES;
}

const zoneLabel = (tz) => tz.split('/').pop().replace(/_/g, ' ');

$('btnCities').onclick = () => openSheet('Cities', buildCities);

function buildCities(body) {
  body.appendChild(el('p', 'hint',
    'Tap a name to rename it. Order here is the order on screen.'));

  const list = el('ul', 'citylist');
  S.cities.forEach((c, i) => {
    const row = el('li', 'cityrow');

    const name = document.createElement('input');
    name.type = 'text';
    name.value = c.label;
    name.setAttribute('aria-label', 'City name');
    name.oninput = () => {
      S.cities[i].label = name.value;
      save();
      if (lastLocal) renderWorld(new Date(), lastLocal);
    };

    const up = el('button', null, '↑');
    up.setAttribute('aria-label', 'Move up');
    up.disabled = i === 0;
    up.onclick = () => { swapCity(i, i - 1); };

    const down = el('button', null, '↓');
    down.setAttribute('aria-label', 'Move down');
    down.disabled = i === S.cities.length - 1;
    down.onclick = () => { swapCity(i, i + 1); };

    const del = el('button', null, '✕');
    del.setAttribute('aria-label', `Remove ${c.label}`);
    del.onclick = () => {
      S.cities.splice(i, 1);
      save(); redrawCities();
    };

    const meta = el('div');
    meta.style.flex = '1 1 auto';
    meta.style.minWidth = '0';
    meta.appendChild(name);
    meta.appendChild(el('div', 'tz', c.tz));

    row.append(meta, up, down, del);
    list.appendChild(row);
  });
  body.appendChild(list);

  /* --- add --- */
  body.appendChild(el('h3', null, 'Add a city')).style.cssText =
    'font-size:13px;letter-spacing:.08em;text-transform:uppercase;margin:4px 0 8px';

  const search = document.createElement('input');
  search.type = 'search';
  search.className = 'search';
  search.placeholder = 'Search time zones…';
  search.setAttribute('aria-label', 'Search time zones');
  body.appendChild(search);

  const results = el('ul', 'results');
  body.appendChild(results);

  const zones = allZones();
  function draw(q) {
    const needle = q.trim().toLowerCase();
    const hits = (needle
      ? zones.filter((z) => z.toLowerCase().replace(/_/g, ' ').includes(needle))
      : zones
    ).slice(0, 60);

    results.innerHTML = '';
    if (!hits.length) {
      results.appendChild(el('li', null, 'No match')).style.padding = '10px 4px';
      return;
    }
    hits.forEach((tz) => {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.innerHTML = `${esc(zoneLabel(tz))}<span class="zone">${esc(tz)}</span>`;
      b.onclick = () => {
        S.cities.push({ tz, label: zoneLabel(tz) });
        save(); redrawCities();
      };
      li.appendChild(b);
      results.appendChild(li);
    });
  }
  search.oninput = () => draw(search.value);
  draw('');
}

function swapCity(a, b) {
  const t = S.cities[a];
  S.cities[a] = S.cities[b];
  S.cities[b] = t;
  save(); redrawCities();
}

function redrawCities() {
  $sheetBody.innerHTML = '';
  buildCities($sheetBody);
  if (lastLocal) renderWorld(new Date(), lastLocal);
}

/* ------------------------------------------------- service worker + updates */

const SW_OK = 'serviceWorker' in navigator;
/* Whether a worker was already in charge when this page loaded. On a first-ever
   visit there is none, and clients.claim() would otherwise trigger a pointless
   reload immediately after install. */
const HAD_CONTROLLER = SW_OK && !!navigator.serviceWorker.controller;

let swReg = null;
let reloading = false;

/** Version string reported by the worker currently serving this page. */
async function activeVersion() {
  if (!SW_OK) return null;
  const reg = swReg || await navigator.serviceWorker.getRegistration();
  const worker = (reg && reg.active) || navigator.serviceWorker.controller;
  if (!worker) return null;

  return new Promise((resolve) => {
    const ch = new MessageChannel();
    const bail = setTimeout(() => resolve(null), 600);
    ch.port1.onmessage = (e) => { clearTimeout(bail); resolve(e.data); };
    worker.postMessage({ type: 'VERSION' }, [ch.port2]);
  });
}

/** For the corner badge: ask the worker, else read VERSION out of sw.js itself.
    Keeping sw.js the only place the number appears means the two can't drift. */
async function resolveVersion() {
  const fromWorker = await activeVersion();
  if (fromWorker) return fromWorker;
  try {
    const res = await fetch('sw.js', { cache: 'no-store' });
    const m = (await res.text()).match(/const VERSION\s*=\s*'([^']+)'/);
    return m ? m[1] : null;
  } catch {
    return null;   // opened from file:// — nothing to report
  }
}

function showVersion() {
  resolveVersion().then((v) => { if (v) $('version').textContent = `v${v}`; });
}

if (SW_OK) {
  window.addEventListener('load', async () => {
    try {
      // updateViaCache:'none' keeps the HTTP cache from hiding a new worker
      swReg = await navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' });
    } catch {
      return;   // e.g. plain http:// over the LAN — not a secure context
    }

    /* A new worker taking control means the markup and CSS on screen are from
       the previous release, so reload once to pick up the new shell. */
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!HAD_CONTROLLER || reloading) return;
      reloading = true;
      location.reload();
    });

    const check = () => { if (swReg) swReg.update().catch(() => {}); };
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') check();
    });
    // an installed PWA can sit open for days without ever re-requesting sw.js
    setInterval(check, 30 * 60 * 1000);
  });
}

/* ------------------------------------------------------------------ boot */

applyChrome();
applyWake();
showVersion();
tick();
