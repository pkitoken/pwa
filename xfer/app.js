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
const ADMIN_PUB = 'BI4IlzF4W6nOF6Ew9yu541CIAJg5lwKsVldXVLihsQHG7_tkAb9RpW2ULGcHDrmDJgdzM07-5cXu2l5ZsyBhZFM';

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
    /* 类型检查，不是 `|| []`——后者挡不住 `{}`。顺便把之前被写坏的文件修回来。 */
    if (!Array.isArray(c.devices)) c.devices = [];
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
async function makePairCode(pass) {
  if (!st.id || !st.cfg) throw new Error('本机还没有身份');
  const bytes = I.packInvite({
    kind: I.KIND_PAIR,
    nonce: C.randHex(8),
    exp: Math.floor(Date.now() / 1000) + PAIR_TTL_MIN * 60,
    dh: st.id.dh, sig: st.id.sig,
    uid: st.id.uid, name: st.id.name,
    repo: st.cfg
  });
  /* 配对码和邀请码一样，一律加密后再显示——屏幕会被人看见，截图会被转手。 */
  const sealed = await I.sealInvite(bytes, pass);
  const url = I.sealedToUrl(location.origin + location.pathname, sealed);
  return { text: I.sealedToText(sealed), url: url, qr: qrSvg(C.utf8(url), { ecl: 1 }) };
}

function showPairSheet() {
  if (needIdentity() || needRepo()) return;
  $('pairTtl').textContent = PAIR_TTL_MIN + ' 分钟';
  $('pairPass').value = '';
  $('pairText').value = '';
  $('pairQr').hidden = true;
  $('pairMeta').hidden = true;
  $('btnPairMore').hidden = true;
  $('pairMoreWrap').hidden = true;
  $('pairState').hidden = true;
  $('pair').hidden = false;
}

async function makePairSheet() {
  const el = $('pairState');
  try {
    const c = I.checkPass($('pairPass').value);
    if (!c.ok) { say(el, c.why, 'err'); return; }
    say(el, '正在加密…（要算几秒）');
    const p = await makePairCode($('pairPass').value);
    $('pairQr').innerHTML = p.qr.svg;
    $('pairQr').hidden = false;
    $('pairMeta').textContent = '版本 ' + p.qr.ver + ' · ' + p.qr.px + 'px · ' +
      PAIR_TTL_MIN + ' 分钟内有效 · 只能用一次';
    $('pairMeta').hidden = false;
    $('pairText').value = p.text;
    $('btnPairMore').hidden = false;
    say(el, '好了。到另一台设备上扫它，然后输入同一句口令。', 'ok');
  } catch (e) {
    say(el, '生成失败：' + e.message, 'err');
  }
}

/* ---------------------------------------------------------- 已登记设备 */

async function renderDevices() {
  const ul = $('devList');
  ul.textContent = '';
  if (!st.id || !st.cfg || !st.cfg.token) return;
  let c = null;
  try { c = await S.readJson(st.cfg, 'claims/' + st.id.uid + '.json'); } catch (e) { return; }
  if (!c || !Array.isArray(c.devices)) return;
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

  /* 没钉公钥就直接拒绝，不再「跳过验签照常用」。
     验签这种东西一旦悄悄失效，界面看着一切正常，反而最危险——
     1.11 之前就是这样：ADMIN_PUB 为空时花名册照收，谁也看不出来。 */
  if (!ADMIN_PUB) throw new Error('这个版本没有钉入管理员公钥，拒绝使用任何花名册');
  const ok = await C.verifyRoster(raw.body, raw.sig || '', ADMIN_PUB);
  if (!ok) throw new Error('花名册签名不对——有人动过它，已拒绝使用');

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

/* ---------------------------------------------------------- 令牌轮换 */

/* 管理员换了 PAT，就把新令牌用每个人的公钥各封装一份，写成 token.json。
   各设备刷新时自己取回来换掉，不用你挨个通知——和股票那套 inbox-token.json
   同一个路子。

   两条必须守住的规矩：
   1. 这份东西**必须由管理员签名**，且签名公钥要等于应用里钉死的 ADMIN_PUB。
      否则任何拿着当前令牌的人都能发一份「新令牌」，把所有人骗到他自己的仓库去。
   2. 换发要有重叠期：**先发布新令牌，等大家取到了，再去 GitHub 吊销旧的**。
      顺序反了，所有人都连不上，也就取不到新的了。 */
async function pickupToken() {
  if (!ADMIN_PUB) return;                     /* 没钉公钥就不敢自动换 */
  let t = null;
  try { t = await S.readJson(st.cfg, 'token.json'); } catch (e) { return; }
  if (!t || !t.ts || !t.blob) return;

  const seen = (await S.kvGet('tokenTs')) || 0;
  if (t.ts <= seen) return;                   /* 处理过了 */

  const entry = { id: t.id, epk: t.epk, recips: t.recips || [] };
  if (!entry.recips.some((r) => r.kid === st.id.kid)) {
    /* 这次轮换没带上我——多半是被移出圈子了。记下时间戳，别每次都重试。 */
    await S.kvSet('tokenTs', t.ts);
    return;
  }
  try {
    const r = await C.open(entry, C.unb64(t.blob), st.keys.dhPriv, st.id.kid);
    if (!r.trusted || r.meta.from.sig !== ADMIN_PUB) {
      toast('有人发了一份假的令牌更新，已忽略', 5000);
      return;
    }
    const tok = C.fromUtf8(r.data).trim();
    if (tok && tok !== st.cfg.token) {
      const old = st.cfg.token;
      st.cfg.token = tok;

      /* 立刻用新凭据写一条回执。一举两得：
         一是先验证新的确实能用，不能用就退回旧的——否则管理员发错了东西，
         所有人会在旧的被吊销那一刻集体失联，而且谁都不知道为什么；
         二是管理员那边能看到「谁已经换过来了」，不必靠猜来决定什么时候
         去吊销旧的那条。 */
      try {
        await S.transact(st.cfg, async (idx, ctx) => {
          const path = 'claims/' + st.id.uid + '.json';
          const c = (await ctx.read(path)) ||
                    { uid: st.id.uid, max: 4, nonces: {}, devices: [] };
          c.tokenTs = t.ts;
          return {
            message: '换用新凭据 ' + st.id.uid,
            puts: [{ path: path, b64: C.b64(C.utf8(JSON.stringify(c, null, 1))) }]
          };
        });
      } catch (e) {
        st.cfg.token = old;                 /* 新的用不了，退回去，下次再试 */
        toast('收到一份新凭据，但它用不了——先继续用旧的', 5000);
        return;
      }
      await S.kvSet('repo', st.cfg);
      toast('访问凭据已自动更新');
    }
    await S.kvSet('tokenTs', t.ts);
  } catch (e) { /* 解不开就算了，下次再说 */ }
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
    await pickupToken();
    await flushAcks();
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
    /* 用户手里已经没有任何可调的开关了，所以别抛术语——直接说下一步做什么 */
    toast((e.status === 401 || e.status === 403)
      ? '这台设备的访问权限失效了——找管理员要一张新的邀请码'
      : e.message, 5000);
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
  /* 发给自己的文件，发件的那台设备要藏起来——否则它自己就把自己发的
     收了，另一台还没来得及取，文件已经按「下载后删除」清掉了。
     st.sent 是本机发件记录，另一台设备没有，所以那边照常显示。 */
  const sentHere = {};
  for (const r of st.sent) sentHere[r.id] = true;

  const mine = (st.index ? st.index.entries : [])
    .filter((e) => e.recips.some((r) => r.kid === kid) && !sentHere[e.id])
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
    const bytes = await S.readBytes(st.cfg, 'blobs/' + e.id + '.bin', null, (got, total) => {
      btn.textContent = total
        ? '下载中 ' + Math.floor(got * 100 / total) + '%'
        : '下载中 ' + fmtSize(got);
    });
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
  } catch (err) {
    if (err && err.name === 'AbortError') { btn.disabled = false; return; }  /* 用户自己取消 */
    toast('保存失败：' + (err && err.message ? err.message : err), 4000);
    btn.disabled = false;
    return;
  }

  /* 回执是另一件事，失败不该说成「保存失败」——文件已经在手上了。
     慢链路上这一步很容易超时，所以记进队列，下次刷新自动补上；补不上也只是
     发件人那边显示「未下载」，密文多留一会儿，没有东西会丢。 */
  try {
    await ack(e.id);
  } catch (err) {
    await queueAck(e.id);
    toast('文件已存好。回执没发出去——下次刷新会自动补。', 5000);
  }
  renderInbox();
}

async function queueAck(id) {
  const q = (await S.kvGet('ackQueue')) || [];
  if (q.indexOf(id) < 0) q.push(id);
  await S.kvSet('ackQueue', q);
}

/* 每次刷新收件箱时把欠着的回执补掉 */
async function flushAcks() {
  const q = (await S.kvGet('ackQueue')) || [];
  if (!q.length) return;
  const left = [];
  for (const id of q) {
    try { await ack(id); } catch (e) { left.push(id); }
  }
  await S.kvSet('ackQueue', left);
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
  hint.textContent = groups.length
    ? '只列出和你同组的人。你在：' + groups.join('、')
    : '你还没被分到任何组——只能发给自己的其它设备。';

  /* 传给自己：手机 ↔ 电脑。两台设备用的是同一个身份、同一个 kid，所以
     收件人写的还是自己那把公钥，发件的这台会把这条从自己的收件箱里藏起来
     （见 renderInbox），免得自己把自己发的文件又「收」一遍。 */
  {
    const div = document.createElement('div');
    div.className = 'group';
    const h = document.createElement('div');
    h.className = 'gname';
    h.textContent = '我自己';
    div.appendChild(h);

    const lab = document.createElement('label');
    lab.className = 'person';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.dataset.kid = self.kid;
    cb.checked = sel.has(self.kid);
    cb.onchange = () => {
      if (cb.checked) sel.add(self.kid); else sel.delete(self.kid);
    };
    const nm = document.createElement('span');
    nm.className = 'pn';
    nm.textContent = '我的其它设备';
    const kk = document.createElement('span');
    kk.className = 'pk';
    kk.textContent = '手机 ↔ 电脑';
    lab.appendChild(cb);
    lab.appendChild(nm);
    lab.appendChild(kk);
    div.appendChild(lab);

    const note = document.createElement('div');
    note.className = 'gname';
    note.style.marginTop = '4px';
    note.textContent = '有三台以上设备时：选「下载后删除」是谁先取谁拿到，' +
                       '想每台都拿一份就挑按天保留的。';
    div.appendChild(note);
    box.appendChild(div);
  }

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
    if (p) recips.push({ kid: p.kid, dh: p.dh, name: p.kid === st.id.kid ? '我的其它设备' : p.name });
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

  $('setDev').textContent = st.dev || '—';
  renderDevices();
  $('who').textContent = st.id ? st.id.name : '未导入身份';
}

/* ------------------------------------------------------- Service Worker */

/* 先问 service worker；它还没接管（比如第一次打开）就直接把 sw.js 拉下来
   读里面的 VERSION——总比显示一个「—」强，而那恰恰是你最想知道版本的时候。 */
function swVersion() {
  return new Promise((res) => {
    const fallback = () => {
      fetch('sw.js', { cache: 'no-store' })
        .then((r) => r.text())
        .then((t) => {
          const m = t.match(/VERSION\s*=\s*'([^']+)'/);
          res(m ? m[1] : '—');
        })
        .catch(() => res('—'));
    };
    if (!navigator.serviceWorker || !navigator.serviceWorker.controller) return fallback();
    const ch = new MessageChannel();
    ch.port1.onmessage = (e) => res(e.data);
    navigator.serviceWorker.controller.postMessage({ type: 'VERSION' }, [ch.port2]);
    setTimeout(fallback, 1500);
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

  /* 扫码带进来的地址，可能通过三条不同的路径到达，Safari 走哪条并不确定：
       · 全新加载        → boot() 里处理
       · 同文档改 #      → hashchange
       · 标签页被恢复    → pageshow / 重新可见，前两个都可能不触发
     三个入口都接上。takeHashInvite() 读完立刻把 # 抹掉，所以重复触发无害。 */
  window.addEventListener('hashchange', () => handleScanned(takeHashInvite()));
  window.addEventListener('pageshow', () => handleScanned(takeHashInvite()));
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) handleScanned(takeHashInvite());
  });

  $('pick').onclick = () => $('file').click();
  $('pick').onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') $('file').click(); };
  $('file').onchange = () => {
    st.picked = Array.prototype.slice.call($('file').files || []);
    updateFileLabel();
  };
  $('btnSend').onclick = send;


  $('btnImport').onclick = () => {
    /* 手动打开时清空，免得上一次失败留下的内容被当成新扫到的 */
    $('inviteText').value = '';
    $('invitePass').value = '';
    $('passWrap').hidden = true;
    $('scanInfo').hidden = true;
    $('iosWarn').hidden = true;
    $('inviteState').hidden = true;
    $('setup').hidden = false;
  };
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
      $('scanInfo').hidden = true;
      lastScanFp = null;
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
  $('btnPairMake').onclick = makePairSheet;
  $('btnPairClose').onclick = () => { $('pair').hidden = true; };
  $('btnPairCopy').onclick = () => copyText($('pairText').value);
  $('btnPairMore').onclick = () => {
    $('pairMoreWrap').hidden = !$('pairMoreWrap').hidden;
    $('btnPairMore').textContent = $('pairMoreWrap').hidden ? '其它方式（笔记本扫不了码时用）' : '收起';
  };

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
  const v = await swVersion();
  $('ver').textContent = v;
  $('verTop').textContent = 'v' + v;

  if (scanned) handleScanned(scanned);
  else if (!st.id) {
    $('setup').hidden = false;
  } else if (st.cfg && st.cfg.token) {
    refreshInbox();
  }
}

/* 扫码带进来的邀请：boot 时要处理，**hashchange 时同样要处理**。

   为什么：如果这个页面已经在 Safari 里开着（比如你早就装好了），再扫一张
   指向同一地址、只是 # 后面不同的码，浏览器认为还是同一个文档——它不会重新
   加载，只会触发 hashchange。boot() 根本不会再跑一遍，于是屏幕上什么也没发生，
   你看到的还是那个已登记的界面。第二次有时又好了，因为标签页碰巧被回收重开了。
   这就是「时灵时不灵」的由来。 */
/* 两张邀请码摆在一起长得一模一样（都是一大段 base64），光看内容根本分不清
   刚扫的是新的还是上一张。所以给每张算个短指纹显示出来，再标上到达时间。 */
async function fingerprint(text) {
  const h = await crypto.subtle.digest('SHA-256', C.utf8(text));
  return C.hex(new Uint8Array(h).subarray(0, 3));
}

let lastScanFp = null;

async function handleScanned(scanned) {
  if (!scanned) return;
  const fp = await fingerprint(scanned);
  const now = new Date();
  const p2 = (x) => String(x).padStart(2, '0');
  const clock = p2(now.getHours()) + ':' + p2(now.getMinutes()) + ':' + p2(now.getSeconds());

  $('inviteText').value = scanned;
  /* 别让内容处于选中状态——看着像是「上一张还留在这儿」 */
  try { $('inviteText').setSelectionRange(0, 0); $('inviteText').blur(); } catch (e) {}

  say($('scanInfo'), fp === lastScanFp
    ? '⟳ 这张码刚才已经扫过了（指纹 ' + fp + '，' + clock + '）——不是新的。'
    : '✓ 刚扫到一张新码：指纹 ' + fp + ' · ' + clock,
    fp === lastScanFp ? '' : 'ok');
  lastScanFp = fp;

  const needPass = I.isSealedText(scanned);
  $('passWrap').hidden = !needPass;
  $('invitePass').value = '';
  $('iosWarn').hidden = true;
  $('inviteState').hidden = true;
  $('setup').hidden = false;

  /* iOS 的主屏应用有独立的存储空间，在 Safari 里导入，主屏图标里是看不到的。
     所以这种情况不自动领取——一旦领了，那张一次性码就白白烧掉了。 */
  const inSafari = isIOS() && !isStandalone();
  if (inSafari) {
    say($('iosWarn'),
      '你在 Safari 里。iOS 主屏应用的存储是独立的，在这儿导入，主屏图标里是空的。' +
      '照这个顺序来：① 点下面的「复制」 ② 分享 → 添加到主屏幕 ③ 打开主屏那个图标 ' +
      '④ 点「从剪贴板粘贴」' + (needPass ? ' ⑤ 填口令，导入。' : ' ⑤ 导入。'), 'err');
  } else if (needPass) {
    say($('iosWarn'), '扫到的是口令加密件。把对方念的那句口令填在下面，再点「导入」。');
  } else {
    $('btnInviteOk').click();
  }
}

boot();
