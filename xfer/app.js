/* =========================================================================
   文件互传 —— 界面与流程。无依赖、无构建步骤。

   身份、令牌、发件记录都放在本机 IndexedDB；服务器那边只有一个私有 Git
   仓库，存密文和一份假名索引。整套东西没有后端。
   ========================================================================= */

import * as C from './crypto.js';
import * as S from './store.js';
import * as I from './invite.js';
import { qrSvg } from './qr.js';

/* 管理员验签公钥（base64url 原始 P-256 公钥）。花名册必须由这把钥匙签过，
   否则应用拒绝使用——否则任何拿到令牌的人都能把别人的公钥换成自己的，
   从此静默接收本该发给别人的文件。用 admin.html 生成后粘到这里。 */
const ADMIN_PUB = '';

const MAX_FILE = 20 * 1024 * 1024;   /* 单个文件上限；base64 后约 27 MB，
                                        再大手机内存和 API 都不舒服 */
const ACK_BACKSTOP_DAYS = 30;        /* 「下载后删除」的兜底期限 */
const DEFAULT_MAX_DEVICES = 4;       /* 一个身份默认最多几台设备 */
const PAIR_TTL_MIN = 10;             /* 设备配对码的有效期（分钟） */

/* ------------------------------------------------------------------ 状态 */

const st = {
  id: null,        /* {uid,name,kid,dh,sig}   dh/sig 为私钥 JWK */
  cfg: null,       /* {owner,repo,branch,token} */
  roster: null,    /* {v,ts,people:[{uid,name,groups,dh,sig,kid}]} */
  sent: [],        /* 本机发件记录 */
  keys: null,      /* {dhPriv,sigPriv,sigPub} 运行时导入的 CryptoKey */
  index: null,     /* 最近一次读到的索引 */
  peek: {},        /* entry.id -> 解开的摘要 {n,s,f} */
  opened: {},      /* entry.id -> 已解密但还没存盘的 {meta,data,who} */
  dev: null,       /* 本机设备号 */
  picked: []       /* 已选文件 */
};

const sel = new Set();   /* 已勾选收件人的 kid */

/* ------------------------------------------------------------------ 工具 */

const $ = (id) => document.getElementById(id);

function toast(msg, ms) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms || 2600);
}

function say(el, msg, kind) {
  el.textContent = msg;
  el.className = 'state' + (kind ? ' ' + kind : '');
  el.hidden = !msg;
}

/* File.arrayBuffer() 在老一点的 iOS Safari 上没有，退回 FileReader。 */
function readFile(f) {
  if (f.arrayBuffer) return f.arrayBuffer();
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.onerror = () => rej(new Error('读文件失败'));
    r.readAsArrayBuffer(f);
  });
}

async function copyText(t) {
  try { await navigator.clipboard.writeText(t); toast('已复制'); }
  catch { toast('复制不了，长按选中再复制吧'); }
}

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function fmtTime(ms) {
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
         ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

function policyText(p) {
  return p === 'ack' ? '下载后删除' : p + ' 天后删除';
}

/* 一条索引条目是否该被清掉。发件端、收件端、定时任务用的是同一套判断，
   所以谁先跑到都得出一样的结论。 */
function dead(e, now) {
  const acks = e.acks || [];
  if (e.p === 'ack') {
    if (e.recips.every((r) => acks.indexOf(r.kid) >= 0)) return true;
    return now - e.ts > ACK_BACKSTOP_DAYS * 86400000;
  }
  const days = Number(e.p);
  return days > 0 && now - e.ts > days * 86400000;
}

function needIdentity() {
  if (!st.id) { toast('先在「设置」里导入身份'); return true; }
  return false;
}

function needRepo() {
  if (!st.cfg || !st.cfg.token || !st.cfg.owner) { toast('先在「设置」里填仓库和令牌'); return true; }
  return false;
}

/* -------------------------------------------------------------- 设备身份 */

/* 每台设备一个随机编号，只用来在领取记录里区分「几台设备用过这个身份」。
   它不是凭据——拿到它做不了任何事。 */
async function deviceId() {
  let d = await S.kvGet('device');
  if (!d) { d = C.randHex(8); await S.kvSet('device', d); }
  return d;
}

function deviceLabel() {
  const ua = navigator.userAgent || '';
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad'
           : /Android/.test(ua) ? 'Android' : /Macintosh/.test(ua) ? 'Mac'
           : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '未知设备';
  const br = /CriOS|Chrome/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox'
           : /Safari/.test(ua) ? 'Safari' : '';
  const mode = isStandalone() ? '主屏' : '浏览器';
  return os + (br ? ' ' + br : '') + ' · ' + mode;
}

function isStandalone() {
  return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
         navigator.standalone === true;
}

function isIOS() {
  const ua = navigator.userAgent || '';
  return /iPad|iPhone|iPod/.test(ua) ||
         (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

/* -------------------------------------------------------------- 身份导入 */

/* 领取：把 nonce 烧掉并把这台设备登记进 claims/<uid>.json。
   同一张码第二次来就会撞上已烧掉的 nonce，直接拒绝——这就是「一次性」。
   注意这挡的是身份，挡不住令牌：谁偷拍了二维码，令牌当场就到手了，
   真要作废只能去 GitHub 换一条 PAT。 */
async function claimInvite(cfg, inv, dev) {
  const path = 'claims/' + inv.uid + '.json';
  await S.transact(cfg, async (idx, ctx) => {
    const c = (await ctx.read(path)) ||
              { uid: inv.uid, max: DEFAULT_MAX_DEVICES, nonces: {}, devices: [] };
    if (c.nonces && c.nonces[inv.nonce]) {
      throw new Error(inv.kind === I.KIND_PAIR
        ? '这张配对码已经用过了，回原设备再生成一张。'
        : '这张邀请码已经被领取过了。让管理员重发一张，或者在已登记的设备上用「添加我的另一台设备」。');
    }
    c.nonces = c.nonces || {};
    c.devices = c.devices || [];
    const known = c.devices.some((d) => d.id === dev);
    const max = c.max || DEFAULT_MAX_DEVICES;
    if (!known && c.devices.length >= max) {
      throw new Error('这个身份已经登记了 ' + max + ' 台设备，到上限了。让管理员放宽或清掉旧设备。');
    }
    c.nonces[inv.nonce] = { at: Date.now(), dev: dev };
    if (!known) c.devices.push({ id: dev, at: Date.now(), ua: deviceLabel(), how: inv.kind === I.KIND_PAIR ? 'pair' : 'admin' });
    return {
      message: '领取 ' + inv.uid + ' · ' + inv.nonce.slice(0, 6),
      puts: [{ path: path, b64: C.b64(C.utf8(JSON.stringify(c, null, 1))) }]
    };
  });
}

async function applyInvite(inv) {
  const now = Math.floor(Date.now() / 1000);
  if (inv.exp && now > inv.exp) {
    throw new Error('这张码已经过期了（' + fmtTime(inv.exp * 1000) + '），让对方重新生成。');
  }
  if (!inv.repo || !inv.repo.token) throw new Error('邀请码里没有访问令牌');

  /* 先把私钥真的导进 WebCrypto 一次，坏钥匙当场就报错，不会等到发文件时才炸 */
  const dhPriv = await C.importDhPriv(inv.dh);
  const sigPriv = await C.importSigPriv(inv.sig);
  const pub = C.pubFromJwk(inv.dh);
  const kid = await C.kidOf(pub);

  const cfg = {
    owner: inv.repo.owner, repo: inv.repo.repo,
    branch: inv.repo.branch || 'main', token: inv.repo.token
  };

  /* 先去仓库把号烧掉。烧不成（码用过了、令牌不对、设备超额）就什么都不落盘，
     免得本机看着像导入成功、实际根本收发不了。 */
  const dev = await deviceId();
  await claimInvite(cfg, inv, dev);

  st.id = {
    uid: inv.uid, name: inv.name || inv.uid, kid: kid,
    dh: inv.dh, sig: inv.sig, dhPub: pub, sigPub: C.pubFromJwk(inv.sig)
  };
  st.keys = { dhPriv, sigPriv };
  st.cfg = cfg;
  await S.kvSet('identity', st.id);
  await S.kvSet('repo', cfg);
}

/* ---------------------------------------------------------- 配对新设备 */

/* 已登记的设备现场生成一张新码：同一个身份、新的 nonce、十分钟有效。
   管理员那张一次性码用掉之后，加设备就靠这个，不用再找管理员。 */
async function makePairCode() {
  if (!st.id || !st.cfg) throw new Error('本机还没有身份');
  const bytes = I.packInvite({
    kind: I.KIND_PAIR,
    nonce: C.randHex(8),
    exp: Math.floor(Date.now() / 1000) + PAIR_TTL_MIN * 60,
    dh: st.id.dh, sig: st.id.sig,
    uid: st.id.uid, name: st.id.name,
    repo: st.cfg
  });
  const url = I.inviteToUrl(location.origin + location.pathname, bytes);
  return { text: I.inviteToText(bytes), url: url, qr: qrSvg(C.utf8(url), { ecl: 1 }) };
}

async function showPairSheet() {
  if (needIdentity() || needRepo()) return;
  try {
    const p = await makePairCode();
    $('pairTtl').textContent = PAIR_TTL_MIN + ' 分钟';
    $('pairQr').innerHTML = p.qr.svg +
      '<div class="qrmeta">版本 ' + p.qr.ver + ' · ' + p.qr.size + '×' + p.qr.size + ' 模块 · ' +
      p.qr.px + 'px · 离屏幕 20–30 厘米扫</div>';
    $('pairText').value = p.text;
    $('pair').hidden = false;
  } catch (e) {
    toast('生成配对码失败：' + e.message, 4000);
  }
}

/* ---------------------------------------------------------- 已登记设备 */

async function renderDevices() {
  const ul = $('devList');
  ul.textContent = '';
  if (!st.id || !st.cfg || !st.cfg.token) return;
  let c = null;
  try { c = await S.readJson(st.cfg, 'claims/' + st.id.uid + '.json'); } catch (e) { return; }
  if (!c || !c.devices) return;
  const mine = await deviceId();
  for (const d of c.devices) {
    const li = document.createElement('li');
    li.className = 'item';
    const n = document.createElement('div');
    n.className = 'n';
    n.textContent = d.ua + (d.id === mine ? '（本机）' : '');
    li.appendChild(n);
    const m = document.createElement('div');
    m.className = 'm';
    m.textContent = fmtTime(d.at) + ' 登记 · ' + (d.how === 'pair' ? '设备配对' : '管理员发码') +
                    ' · ' + d.id.slice(0, 8);
    li.appendChild(m);
    ul.appendChild(li);
  }
}

/* ------------------------------------------------------------- 花名册 */

async function loadRoster(quiet) {
  if (needRepo()) return null;
  const raw = await S.readJson(st.cfg, 'roster.json');
  if (!raw || !raw.body) throw new Error('仓库里没有 roster.json');

  if (!ADMIN_PUB) {
    if (!quiet) toast('警告：应用里没写管理员公钥，花名册未验签');
  } else {
    const ok = await C.verifyRoster(raw.body, raw.sig || '', ADMIN_PUB);
    if (!ok) throw new Error('花名册签名不对——有人动过它，已拒绝使用');
  }

  const body = JSON.parse(raw.body);
  for (const p of body.people) p.kid = await C.kidOf(p.dh);
  st.roster = body;
  await S.kvSet('roster', body);
  return body;
}

function me() {
  if (!st.roster || !st.id) return null;
  return st.roster.people.find((p) => p.kid === st.id.kid) || null;
}

function personByKid(kid) {
  return st.roster ? st.roster.people.find((p) => p.kid === kid) : null;
}

/* ------------------------------------------------------------- 收件流程 */

async function refreshInbox() {
  if (needIdentity() || needRepo()) return;
  const hint = $('inboxHint');
  hint.textContent = '正在检查…';
  try {
    /* 每次刷新都顺手拉一次花名册——管理员改了分组，这边才跟得上；否则本机
       缓存的那份能用一辈子。拉不到就继续用旧的，不影响收文件。 */
    try { await loadRoster(true); renderRecips(); } catch (e) { /* 收件不强依赖花名册 */ }
    const idx = await S.readJson(st.cfg, 'index.json') || { v: 1, entries: [] };
    st.index = idx;
    await purgeIfNeeded(idx);

    /* 先把属于自己的条目的摘要解开，界面才好显示文件名和发件人 */
    const kid = st.id.kid;
    for (const e of st.index.entries) {
      if (st.peek[e.id]) continue;
      if (!e.recips.some((r) => r.kid === kid)) continue;
      st.peek[e.id] = await C.peek(e, st.keys.dhPriv, kid) || {};
    }
    renderInbox();
    hint.textContent = '最后检查 ' + fmtTime(Date.now());
  } catch (e) {
    hint.textContent = '';
    toast(e.message);
  }
}

/* 顺手清理：任何人打开应用都会把该删的删掉，不必等定时任务。 */
async function purgeIfNeeded(idx) {
  const now = Date.now();
  const gone = idx.entries.filter((e) => dead(e, now));
  if (!gone.length) return;
  try {
    await S.transact(st.cfg, (fresh) => {
      const drop = fresh.entries.filter((e) => dead(e, Date.now()));
      if (!drop.length) return null;
      return {
        message: '清理 ' + drop.length + ' 份到期文件',
        index: { v: 1, entries: fresh.entries.filter((e) => !dead(e, Date.now())) },
        dels: drop.map((e) => 'blobs/' + e.id + '.bin')
      };
    });
    st.index.entries = idx.entries.filter((e) => !dead(e, now));
  } catch (e) {
    /* 清理失败不影响收发，下次再说 */
  }
}

function renderInbox() {
  const ul = $('inbox');
  ul.textContent = '';
  const kid = st.id ? st.id.kid : '';
  const mine = (st.index ? st.index.entries : [])
    .filter((e) => e.recips.some((r) => r.kid === kid))
    .sort((a, b) => b.ts - a.ts);

  $('inboxEmpty').hidden = mine.length > 0;
  if (!mine.length) { $('inboxEmpty').textContent = '没有发给你的文件。'; return; }

  for (const e of mine) {
    const got = (e.acks || []).indexOf(kid) >= 0;
    const li = document.createElement('li');
    li.className = 'item';

    const pv = st.peek[e.id] || {};
    const n = document.createElement('div');
    n.className = 'n';
    n.textContent = pv.n || '（文件名待解密）';
    li.appendChild(n);

    const m = document.createElement('div');
    m.className = 'm';
    m.textContent = (pv.f ? pv.f + ' 发来' : '来源未知') +
                    ' · ' + fmtSize(pv.s || e.sz) + ' · ' + fmtTime(e.ts) +
                    ' · ' + policyText(e.p) + ' · 共 ' + e.recips.length + ' 位收件人';
    li.appendChild(m);

    const acts = document.createElement('div');
    acts.className = 'acts';
    const open = st.opened[e.id];
    const b = document.createElement('button');
    b.className = 'btn primary';
    if (open) {
      b.textContent = '保存到文件';
      b.onclick = () => saveOpened(e, b);
    } else {
      b.textContent = got ? '再下载一次' : '下载并解密';
      b.onclick = () => grab(e, b);
    }
    acts.appendChild(b);
    if (open) {
      const t = document.createElement('span');
      t.className = 'tag ok';
      t.textContent = '已解密，等你保存';
      acts.appendChild(t);
    } else if (got) {
      const t = document.createElement('span');
      t.className = 'tag ok';
      t.textContent = '已下载';
      acts.appendChild(t);
    }
    li.appendChild(acts);
    ul.appendChild(li);
  }
}

async function grab(e, btn) {
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = '下载中…';
  try {
    const bytes = await S.readBytes(st.cfg, 'blobs/' + e.id + '.bin');
    if (!bytes) throw new Error('密文不在了——可能已被清理');
    btn.textContent = '解密中…';
    const r = await C.open(e, bytes, st.keys.dhPriv, st.id.kid);

    /* 验签只证明「某把签名钥匙签的」，还要回花名册确认那把钥匙确实属于
       他声称的那个人，才算认证了发件人。 */
    let who = r.meta.from.name || r.meta.from.uid;
    const p = st.roster ? st.roster.people.find((x) => x.uid === r.meta.from.uid) : null;
    if (!r.trusted) who += '（签名不对，来路不明）';
    else if (!st.roster) who += '（花名册没载入，身份未核对）';
    else if (!p || p.sig !== r.meta.from.sig) who += '（花名册里对不上这把钥匙）';

    /* 解完先放在内存里，不当场存盘。原因有两个：
       一是 iOS 上存盘要走系统分享面板，而分享面板必须由一次「新鲜的」点击
       触发——网络请求一等，这次点击的授权就过期了，面板弹不出来或者什么都
       不做；二是存盘那一下可能让页面跳转，把还在飞的回执请求打断，于是
       屏幕上冒出一句莫名其妙的「载入失败」。
       所以分两步：这一步只解密，下一步由用户再点一次来保存。 */
    st.opened[e.id] = { meta: r.meta, data: r.data, who: who };
    toast('已解密：' + r.meta.n + ' — 来自 ' + who, 4200);
    renderInbox();
  } catch (err) {
    toast(err.message, 4000);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

/* 必须是点击处理器里第一时间调用，中间不能有 await，否则 iOS 认为
   用户授权已经过期，navigator.share 会被拒。 */
function shareFile(bytes, name, type) {
  if (!navigator.canShare || !navigator.share || typeof File !== 'function') return null;
  let file;
  try {
    file = new File([bytes], name || 'file.bin', { type: type || 'application/octet-stream' });
  } catch { return null; }
  if (!navigator.canShare({ files: [file] })) return null;
  return navigator.share({ files: [file] });
}

/* a.download 在 iOS（尤其是主屏应用）基本不管用：要么整页跳走，要么弹一个
   点了没反应的下载框。所以先试系统分享面板，那才是 iOS 上「存到文件」的正路。 */
function downloadFile(bytes, name, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type: type || 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name || 'file.bin';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 60000);
}

async function saveOpened(e, btn) {
  const got = st.opened[e.id];
  if (!got) return;
  /* 只在 iOS 上改走分享面板。Android 和桌面的 a.download 本来就好用，
     不去动它——换成分享面板反而多一层选择。 */
  const shared = isIOS() ? shareFile(got.data, got.meta.n, got.meta.t) : null;
  btn.disabled = true;
  try {
    if (shared) {
      await shared;
    } else {
      downloadFile(got.data, got.meta.n, got.meta.t);
    }
    /* 存盘成功才写回执。顺序反过来的话，万一存盘失败而自己又是最后一个
       没下载的人，密文会在同一次提交里被删掉——文件就真没了。 */
    delete st.opened[e.id];
    toast('已保存：' + got.meta.n);
    await ack(e.id);
    renderInbox();
  } catch (err) {
    if (err && err.name === 'AbortError') { btn.disabled = false; return; }  /* 用户自己取消 */
    toast('保存失败：' + (err && err.message ? err.message : err), 4000);
    btn.disabled = false;
  }
}

/* 回执写进索引；如果这是最后一个没下载的人，同一次提交里就把密文删掉。 */
async function ack(id) {
  const kid = st.id.kid;
  await S.transact(st.cfg, (fresh) => {
    const e = fresh.entries.find((x) => x.id === id);
    if (!e) return null;
    const acks = e.acks || [];
    if (acks.indexOf(kid) >= 0 && !dead(e, Date.now())) return null;
    if (acks.indexOf(kid) < 0) acks.push(kid);
    e.acks = acks;
    const now = Date.now();
    const drop = fresh.entries.filter((x) => dead(x, now));
    return {
      message: '回执 ' + id.slice(0, 8) + (drop.length ? '，并清理 ' + drop.length + ' 份' : ''),
      index: { v: 1, entries: fresh.entries.filter((x) => !dead(x, now)) },
      dels: drop.map((x) => 'blobs/' + x.id + '.bin')
    };
  });
  st.index = await S.readJson(st.cfg, 'index.json') || { v: 1, entries: [] };
}

/* ------------------------------------------------------------- 发件流程 */

function renderRecips() {
  const box = $('recips');
  box.textContent = '';
  const hint = $('recipHint');

  const self = me();
  if (!st.roster) { hint.textContent = '花名册没载入，去「设置」里拉一次。'; return; }
  if (!self) { hint.textContent = '花名册里没有你这把钥匙，找管理员把你加进去。'; return; }

  const groups = self.groups || [];
  if (!groups.length) { hint.textContent = '你还没被分到任何组。'; return; }
  hint.textContent = '只列出和你同组的人。你在：' + groups.join('、');

  for (const g of groups) {
    const mates = st.roster.people.filter((p) => p.kid !== self.kid && (p.groups || []).indexOf(g) >= 0);
    if (!mates.length) continue;

    const div = document.createElement('div');
    div.className = 'group';
    const h = document.createElement('div');
    h.className = 'gname';
    h.textContent = g;
    div.appendChild(h);

    for (const p of mates) {
      const lab = document.createElement('label');
      lab.className = 'person';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.dataset.kid = p.kid;
      cb.checked = sel.has(p.kid);
      cb.onchange = () => {
        if (cb.checked) sel.add(p.kid); else sel.delete(p.kid);
        /* 同一个人可能同时出现在两个共同组里，勾一处两处都要跟着动 */
        const all = box.querySelectorAll('input[data-kid="' + p.kid + '"]');
        for (let i = 0; i < all.length; i++) all[i].checked = cb.checked;
      };
      const nm = document.createElement('span');
      nm.className = 'pn';
      nm.textContent = p.name;
      const kk = document.createElement('span');
      kk.className = 'pk';
      kk.textContent = p.kid.slice(0, 8);
      lab.appendChild(cb);
      lab.appendChild(nm);
      lab.appendChild(kk);
      div.appendChild(lab);
    }
    box.appendChild(div);
  }
}

async function send() {
  if (needIdentity() || needRepo()) return;
  const state = $('sendState');
  const files = st.picked;
  if (!files.length) { say(state, '还没选文件。', 'err'); return; }
  if (!sel.size) { say(state, '还没勾选收件人。', 'err'); return; }
  for (const f of files) {
    if (f.size > MAX_FILE) { say(state, '「' + f.name + '」超过 ' + fmtSize(MAX_FILE) + '，太大了。', 'err'); return; }
  }

  const recips = [];
  for (const kid of sel) {
    const p = personByKid(kid);
    if (p) recips.push({ kid: p.kid, dh: p.dh, name: p.name });
  }
  if (!recips.length) { say(state, '收件人在花名册里找不到，先刷新花名册。', 'err'); return; }

  const btn = $('btnSend');
  btn.disabled = true;
  const policy = $('policy').value;
  const now = Date.now();

  try {
    const sealed = [];
    for (let i = 0; i < files.length; i++) {
      say(state, '正在加密 ' + (i + 1) + '/' + files.length + '：' + files[i].name);
      const bytes = new Uint8Array(await readFile(files[i]));
      const s = await C.seal(bytes, { name: files[i].name, type: files[i].type, ts: now }, recips, {
        uid: st.id.uid, name: st.id.name, sigPriv: st.keys.sigPriv, sigPub: st.id.sigPub
      });
      sealed.push({ s: s, size: bytes.length, name: files[i].name });
    }

    say(state, '正在上传…');
    await S.transact(st.cfg, (fresh) => {
      const t = Date.now();
      const keep = fresh.entries.filter((e) => !dead(e, t));
      const drop = fresh.entries.filter((e) => dead(e, t));
      for (const x of sealed) {
        keep.push({
          id: x.s.id, epk: x.s.epk, ts: now, sz: x.s.blob.length, p: policy,
          recips: x.s.recips, acks: []
        });
      }
      return {
        message: '新增 ' + sealed.length + ' 份文件',
        index: { v: 1, entries: keep },
        puts: sealed.map((x) => ({ path: 'blobs/' + x.s.id + '.bin', b64: C.b64(x.s.blob) })),
        dels: drop.map((e) => 'blobs/' + e.id + '.bin')
      };
    });

    for (const x of sealed) {
      st.sent.unshift({
        id: x.s.id, name: x.name, size: x.size, ts: now, p: policy,
        to: recips.map((r) => ({ kid: r.kid, name: r.name }))
      });
    }
    st.sent = st.sent.slice(0, 200);
    await S.kvSet('sent', st.sent);

    st.picked = [];
    $('file').value = '';
    updateFileLabel();
    sel.clear();
    renderRecips();
    st.index = await S.readJson(st.cfg, 'index.json') || { v: 1, entries: [] };
    renderSent();
    say(state, '发送成功：' + sealed.length + ' 份文件，' + recips.length + ' 位收件人。', 'ok');
  } catch (e) {
    say(state, '发送失败：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function renderSent() {
  const ul = $('sent');
  ul.textContent = '';
  $('sentEmpty').hidden = st.sent.length > 0;

  for (const r of st.sent) {
    const e = st.index ? st.index.entries.find((x) => x.id === r.id) : null;
    const li = document.createElement('li');
    li.className = 'item';

    const n = document.createElement('div');
    n.className = 'n';
    n.textContent = r.name;
    li.appendChild(n);

    const m = document.createElement('div');
    m.className = 'm';
    m.textContent = fmtSize(r.size) + ' · ' + fmtTime(r.ts) + ' · ' + policyText(r.p) +
                    ' · 发给 ' + r.to.map((t) => t.name).join('、');
    li.appendChild(m);

    const acts = document.createElement('div');
    acts.className = 'acts';
    if (!e) {
      const t = document.createElement('span');
      t.className = 'tag';
      t.textContent = '仓库里已清除';
      acts.appendChild(t);
    } else {
      const acks = e.acks || [];
      for (const to of r.to) {
        const t = document.createElement('span');
        const got = acks.indexOf(to.kid) >= 0;
        t.className = 'tag' + (got ? ' ok' : '');
        t.textContent = to.name + (got ? ' 已下载' : ' 未下载');
        acts.appendChild(t);
      }
      const b = document.createElement('button');
      b.className = 'btn danger';
      b.textContent = '撤回';
      b.onclick = () => revoke(r.id, b);
      acts.appendChild(b);
    }
    li.appendChild(acts);
    ul.appendChild(li);
  }
}

async function revoke(id, btn) {
  btn.disabled = true;
  try {
    await S.transact(st.cfg, (fresh) => {
      if (!fresh.entries.some((e) => e.id === id)) return null;
      return {
        message: '撤回 ' + id.slice(0, 8),
        index: { v: 1, entries: fresh.entries.filter((e) => e.id !== id) },
        dels: ['blobs/' + id + '.bin']
      };
    });
    st.index = await S.readJson(st.cfg, 'index.json') || { v: 1, entries: [] };
    renderSent();
    toast('已撤回');
  } catch (e) {
    toast('撤回失败：' + e.message);
  } finally {
    btn.disabled = false;
  }
}

function updateFileLabel() {
  const l = $('fileLabel');
  const box = $('pick');
  if (!st.picked.length) {
    l.textContent = '点这里选择文件（可多选）';
    box.classList.remove('has');
    return;
  }
  const total = st.picked.reduce((a, f) => a + f.size, 0);
  l.textContent = st.picked.map((f) => f.name).join('、') +
                  '　—　共 ' + st.picked.length + ' 个，' + fmtSize(total);
  box.classList.add('has');
}

/* ------------------------------------------------------------------ 设置 */

function renderSettings() {
  $('setName').textContent = st.id ? st.id.name : '—';
  $('setUid').textContent = st.id ? st.id.uid : '—';
  $('setKid').textContent = st.id ? st.id.kid : '—';
  const self = me();
  $('setGroups').textContent = self ? (self.groups || []).join('、') || '（无）' : '—';

  if (st.cfg) {
    $('setRepo').value = st.cfg.owner ? st.cfg.owner + '/' + st.cfg.repo : '';
    $('setBranch').value = st.cfg.branch || 'main';
    $('setToken').value = st.cfg.token || '';
  }
  $('setDev').textContent = st.dev || '—';
  renderDevices();
  $('rosterInfo').textContent = st.roster
    ? '共 ' + st.roster.people.length + ' 人，更新于 ' + fmtTime(st.roster.ts || 0)
    : '未载入。';
  $('who').textContent = st.id ? st.id.name : '未导入身份';
}

async function saveRepo() {
  const v = $('setRepo').value.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
  const parts = v.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    say($('repoState'), '仓库要写成 用户名/仓库名 的形式。', 'err');
    return false;
  }
  st.cfg = {
    owner: parts[0], repo: parts[1],
    branch: $('setBranch').value.trim() || 'main',
    token: $('setToken').value.trim()
  };
  await S.kvSet('repo', st.cfg);
  say($('repoState'), '已保存。', 'ok');
  return true;
}

/* ------------------------------------------------------- Service Worker */

function swVersion() {
  return new Promise((res) => {
    if (!navigator.serviceWorker || !navigator.serviceWorker.controller) return res('—');
    const ch = new MessageChannel();
    ch.port1.onmessage = (e) => res(e.data);
    navigator.serviceWorker.controller.postMessage({ type: 'VERSION' }, [ch.port2]);
    setTimeout(() => res('—'), 1500);
  });
}

function registerSW() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('sw.js').then((reg) => {
    reg.addEventListener('updatefound', () => {
      const w = reg.installing;
      if (!w) return;
      w.addEventListener('statechange', () => {
        /* 有 controller 才说明是升级而不是首次安装 */
        if (w.state === 'installed' && navigator.serviceWorker.controller) {
          toast('有新版本，正在切换…');
          w.postMessage({ type: 'SKIP_WAITING' });
        }
      });
    });
  }).catch(() => {});

  let reloaded = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloaded) return;
    reloaded = true;
    location.reload();
  });
}

/* ------------------------------------------------------------------ 启动 */

function wire() {
  const tabs = document.querySelectorAll('.tabbtn');
  for (let i = 0; i < tabs.length; i++) {
    tabs[i].onclick = () => {
      for (let j = 0; j < tabs.length; j++) tabs[j].classList.toggle('on', tabs[j] === tabs[i]);
      $('tab-inbox').hidden = tabs[i].dataset.tab !== 'inbox';
      $('tab-send').hidden = tabs[i].dataset.tab !== 'send';
      $('tab-set').hidden = tabs[i].dataset.tab !== 'set';
      if (tabs[i].dataset.tab === 'send') { renderRecips(); renderSent(); }
      if (tabs[i].dataset.tab === 'set') renderSettings();
    };
  }

  $('btnRefresh').onclick = refreshInbox;

  $('pick').onclick = () => $('file').click();
  $('pick').onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') $('file').click(); };
  $('file').onchange = () => {
    st.picked = Array.prototype.slice.call($('file').files || []);
    updateFileLabel();
  };
  $('btnSend').onclick = send;

  $('btnSaveRepo').onclick = saveRepo;
  $('btnTest').onclick = async () => {
    if (!await saveRepo()) return;
    say($('repoState'), '正在连接…');
    try {
      const r = await S.probe(st.cfg);
      say($('repoState'), '连上了。' + (r.private ? '私有仓库' : '⚠ 这是公开仓库') +
        '，写权限' + (r.push ? '有' : '没有——只能收，不能发'), r.push ? 'ok' : 'err');
    } catch (e) { say($('repoState'), e.message, 'err'); }
  };
  $('btnRoster').onclick = async () => {
    try { await loadRoster(); renderSettings(); renderRecips(); toast('花名册已更新'); }
    catch (e) { toast(e.message, 4000); }
  };

  $('btnImport').onclick = () => { $('setup').hidden = false; };
  $('btnInviteCancel').onclick = () => { $('setup').hidden = true; };
  $('btnInviteFile').onclick = () => $('inviteFile').click();
  $('inviteFile').onchange = async () => {
    const f = $('inviteFile').files[0];
    if (f) $('inviteText').value = f.text ? await f.text() : await new Promise((res) => {
      const r = new FileReader();
      r.onload = () => res(String(r.result));
      r.readAsText(f);
    });
  };
  $('btnInviteOk').onclick = async () => {
    const el = $('inviteState');
    const btn = $('btnInviteOk');
    btn.disabled = true;
    try {
      const raw = $('inviteText').value;
      let inv;
      if (I.isSealedText(raw)) {
        const c = I.checkPass($('invitePass').value);
        if (!c.ok) throw new Error('口令' + (c.han ? '不够长：' + c.why : '还没填'));
        say(el, '正在按口令解开…（要算几秒，慢是故意的）');
        inv = await I.openSealed(I.sealedFromText(raw), $('invitePass').value);
      } else {
        inv = I.inviteFromText(raw);
      }
      say(el, '正在向仓库登记这台设备…');
      await applyInvite(inv);
      $('inviteText').value = '';
      $('invitePass').value = '';
      $('passWrap').hidden = true;
      try { await loadRoster(true); } catch (e) { /* 花名册还没建好也不挡导入 */ }
      renderSettings();
      renderRecips();
      $('setup').hidden = true;
      toast('身份已导入：' + st.id.name);
      refreshInbox();
    } catch (e) { say(el, e.message, 'err'); }
    finally { btn.disabled = false; }
  };

  $('btnInviteCopy').onclick = () => copyText($('inviteText').value);

  /* iOS 上从 Safari 扫码、再回到主屏应用里导入，中间必然要过一次剪贴板
     （两边存储是分开的）。给个按钮，省得长按对准那点小菜单。 */
  $('btnInvitePaste').onclick = async () => {
    try {
      const t = await navigator.clipboard.readText();
      if (!t) throw new Error('剪贴板是空的');
      $('inviteText').value = t.trim();
      $('passWrap').hidden = !I.isSealedText($('inviteText').value);
      say($('inviteState'), '粘好了' + (I.isSealedText(t) ? '，这是加密件，把口令填上' : ''), 'ok');
    } catch (e) {
      say($('inviteState'), '读不到剪贴板（浏览器可能不允许）——长按输入框手动粘贴吧', 'err');
    }
  };

  /* 粘进来的是口令加密件就把口令框亮出来 */
  const syncPassBox = () => { $('passWrap').hidden = !I.isSealedText($('inviteText').value); };
  $('inviteText').oninput = syncPassBox;
  $('inviteText').onchange = syncPassBox;

  $('btnPair').onclick = showPairSheet;
  $('btnPairClose').onclick = () => { $('pair').hidden = true; };
  $('btnPairCopy').onclick = () => copyText($('pairText').value);

  $('btnWipe').onclick = async () => {
    if (!confirm('清空本机的身份、令牌和发件记录？仓库里的文件不受影响。')) return;
    await S.kvClear();
    location.reload();
  };

  $('btnUpdate').onclick = async () => {
    if (!navigator.serviceWorker) return;
    const reg = await navigator.serviceWorker.getRegistration();
    if (reg) { await reg.update(); toast('已向服务器问过了'); }
  };
}

/* 扫码进来的链接形如 …/xfer/#i=<邀请码>。# 后面的内容不会发给服务器，
   但会留在浏览器历史里，所以读完立刻抹掉。 */
function takeHashInvite() {
  const h = location.hash || '';
  const plain = h.match(/[#&]i=([A-Za-z0-9_\-]+)/);
  const sealed = h.match(/[#&]s=([A-Za-z0-9_\-]+)/);
  if (!plain && !sealed) return null;
  try { history.replaceState(null, '', location.pathname + location.search); }
  catch { location.hash = ''; }
  return sealed ? 'TXF3.' + sealed[1] : 'TXF2.' + plain[1];
}

async function boot() {
  wire();
  registerSW();

  const scanned = takeHashInvite();

  st.dev = await deviceId();
  st.id = await S.kvGet('identity') || null;
  st.cfg = await S.kvGet('repo') || null;
  st.roster = await S.kvGet('roster') || null;
  st.sent = await S.kvGet('sent') || [];

  if (st.id) {
    st.keys = {
      dhPriv: await C.importDhPriv(st.id.dh),
      sigPriv: await C.importSigPriv(st.id.sig)
    };
  }

  renderSettings();
  $('ver').textContent = await swVersion();

  if (scanned) {
    $('inviteText').value = scanned;
    const needPass = I.isSealedText(scanned);
    $('passWrap').hidden = !needPass;
    $('setup').hidden = false;
    /* iOS 的主屏应用有独立的存储空间，在 Safari 里导入，主屏图标里是看不到的。
       所以这种情况下不自动领取——一旦领了，那张一次性码就白白烧掉了。 */
    if (needPass) {
      /* 口令件本来就要人工输入口令，不能自动导入 */
      say($('iosWarn'), '扫到的是口令加密件。把对方电话里念的那句话填在下面，再点「导入」。',
        isIOS() && !isStandalone() ? 'err' : '');
      if (isIOS() && !isStandalone()) {
        say($('iosWarn'),
          '而且你现在是在 Safari 里。iOS 主屏应用的存储是独立的，先「分享 → 添加到主屏幕」，' +
          '打开那个图标再来填口令，否则白白烧掉一张一次性码。', 'err');
      }
    } else if (isIOS() && !isStandalone()) {
      say($('iosWarn'),
        '你现在是在 Safari 里打开的。iOS 的主屏应用有自己独立的存储，' +
        '在这里导入，主屏上的图标里并不会有你的身份。请先「分享 → 添加到主屏幕」，' +
        '打开那个图标，再把上面这段邀请码粘进去（点「复制」）。', 'err');
    } else {
      $('btnInviteOk').click();
    }
  } else if (!st.id) {
    $('setup').hidden = false;
  } else if (st.cfg && st.cfg.token) {
    refreshInbox();
  }
}

boot();
