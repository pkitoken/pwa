/* =========================================================================
   管理台 —— 只给管理员用：发身份、编组、给花名册签名、看领取状态。

   这一页不需要任何秘密就能打开；真正的权力在管理员私钥上，它只存在本机
   localStorage 里。把这页放在公开 Pages 上不会削弱任何安全性。
   ========================================================================= */

import * as C from './crypto.js';
import * as S from './store.js';
import * as I from './invite.js';
import { qrSvg } from './qr.js';

const LS = 'xferadmin.v1';
const $ = (id) => document.getElementById(id);

let A = load();
let CLAIMS = {};          /* uid -> 仓库里的领取记录 */

function load() {
  try {
    const raw = localStorage.getItem(LS);
    if (raw) return JSON.parse(raw);
  } catch {}
  return { admin: null, repo: { owner: '', repo: '', branch: 'main', token: '' }, people: [], keys: {} };
}

function save() { localStorage.setItem(LS, JSON.stringify(A)); }

function toast(m, ms) {
  const t = $('toast');
  t.textContent = m;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms || 2600);
}

function say(msg, kind) {
  const el = $('rosterState');
  el.textContent = msg;
  el.className = 'state' + (kind ? ' ' + kind : '');
  el.hidden = !msg;
}

function fmtTime(ms) {
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
         ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('已复制'); }
  catch { toast('复制失败，手动全选吧'); }
}

/* --------------------------------------------------------- 管理员钥匙 */

function renderAdmin() {
  $('adState').textContent = A.admin ? '已就绪' : '未生成';
  $('adPub').value = A.admin ? A.admin.pub : '';
  $('adRepo').value = A.repo.owner ? A.repo.owner + '/' + A.repo.repo : '';
  $('adBranch').value = A.repo.branch || 'main';
  $('adToken').value = A.repo.token || '';
}

$('btnGenAdmin').onclick = async () => {
  if (A.admin && !confirm('已经有一把管理员钥匙了。换新的会让所有已安装的应用拒收新花名册，确定？')) return;
  const kp = await C.genSig();
  A.admin = { jwk: await C.exportJwk(kp.privateKey), pub: await C.exportPub(kp.publicKey) };
  save(); renderAdmin();
  toast('生成好了。把公钥粘进 app.js 的 ADMIN_PUB。', 5000);
};

$('btnExpAdmin').onclick = () => {
  if (!A.admin) return toast('还没有管理员钥匙');
  download('xfer-admin-key.json', JSON.stringify(A.admin, null, 2));
};

$('btnImpAdmin').onclick = () => {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.json,application/json';
  inp.onchange = async () => {
    try {
      const o = JSON.parse(await inp.files[0].text());
      await C.importSigPriv(o.jwk);              /* 先验一下是不是真钥匙 */
      A.admin = { jwk: o.jwk, pub: o.pub || C.pubFromJwk(o.jwk) };
      save(); renderAdmin(); toast('已导入');
    } catch (e) { toast('导入失败：' + e.message); }
  };
  inp.click();
};

$('btnSaveRepo2').onclick = () => {
  const v = $('adRepo').value.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
  const p = v.split('/');
  if (p.length !== 2 || !p[0] || !p[1]) return toast('仓库要写成 用户名/仓库名');
  A.repo = { owner: p[0], repo: p[1], branch: $('adBranch').value.trim() || 'main', token: $('adToken').value.trim() };
  save(); toast('已保存');
};

/* ------------------------------------------------------------- 成员 */

function parseGroups(s) {
  return (s || '').split(/[,，、;；\s]+/).map((x) => x.trim()).filter(Boolean);
}

$('btnAdd').onclick = async () => {
  const name = $('nwName').value.trim();
  const uid = $('nwUid').value.trim();
  const groups = parseGroups($('nwGroups').value);
  if (!name || !uid) return toast('姓名和代号都要填');
  if (!/^[a-z0-9_.-]+$/i.test(uid)) return toast('代号只用字母数字和 - _ .');
  if (A.people.some((p) => p.uid === uid)) return toast('这个代号已经有人用了');

  const dh = await C.genDh();
  const sg = await C.genSig();
  A.people.push({
    uid, name, groups,
    dh: await C.exportPub(dh.publicKey),
    sig: await C.exportPub(sg.publicKey)
  });
  /* 私钥留在本机，发码时现搭邀请码；发完点「清除本机保存的全部私钥」。 */
  A.keys[uid] = { dh: await C.exportJwk(dh.privateKey), sig: await C.exportJwk(sg.privateKey) };
  save();

  $('nwName').value = ''; $('nwUid').value = '';
  renderPeople();
  toast('已生成 ' + name + ' 的钥匙，点他那条的「发邀请码」');
};

function claimTag(uid) {
  const c = CLAIMS[uid];
  const t = document.createElement('span');
  if (!c) { t.className = 'tag'; t.textContent = '未领取'; return t; }
  const n = (c.devices || []).length;
  t.className = 'tag ok';
  t.textContent = '已领取 · ' + n + '/' + (c.max || 4) + ' 台设备';
  return t;
}

function renderPeople() {
  const ul = $('people');
  ul.textContent = '';
  for (const p of A.people) {
    const li = document.createElement('li');
    li.className = 'item';

    const n = document.createElement('div');
    n.className = 'n';
    n.textContent = p.name + '（' + p.uid + '）';
    li.appendChild(n);

    const c = CLAIMS[p.uid];
    if (c && c.devices && c.devices.length) {
      const m = document.createElement('div');
      m.className = 'm';
      m.textContent = c.devices.map((d) => d.ua + ' ' + fmtTime(d.at)).join('　·　');
      li.appendChild(m);
    }

    const g = document.createElement('label');
    g.className = 'fld';
    g.style.marginTop = '8px';
    const gs = document.createElement('span');
    gs.textContent = '所在组';
    const gi = document.createElement('input');
    gi.className = 'inp';
    gi.value = (p.groups || []).join('、');
    gi.onchange = () => { p.groups = parseGroups(gi.value); save(); toast('改好了，记得重新签名并写入仓库'); };
    g.appendChild(gs); g.appendChild(gi);
    li.appendChild(g);

    const acts = document.createElement('div');
    acts.className = 'acts';
    acts.appendChild(claimTag(p.uid));

    if (A.keys[p.uid]) {
      const b1 = document.createElement('button');
      b1.className = 'btn primary';
      b1.textContent = '发邀请码';
      b1.onclick = () => showInvite(p);
      acts.appendChild(b1);
    } else {
      const t = document.createElement('span');
      t.className = 'tag warn';
      t.textContent = '私钥已清除，只能重发新钥匙';
      acts.appendChild(t);
    }

    if (CLAIMS[p.uid]) {
      const b2 = document.createElement('button');
      b2.className = 'btn';
      b2.textContent = '重置领取';
      b2.onclick = () => resetClaim(p);
      acts.appendChild(b2);
    }

    const del = document.createElement('button');
    del.className = 'btn danger';
    del.textContent = '移除';
    del.onclick = () => {
      if (!confirm('把 ' + p.name + ' 从花名册里移除？签名并写入仓库后他就再也收不到新文件了。')) return;
      A.people = A.people.filter((x) => x.uid !== p.uid);
      delete A.keys[p.uid];
      save(); renderPeople();
    };
    acts.appendChild(del);
    li.appendChild(acts);
    ul.appendChild(li);
  }
}

/* -------------------------------------------------------- 发邀请二维码 */

function showInvite(p) {
  const k = A.keys[p.uid];
  if (!k) return toast('这个人的私钥已经清掉了');
  if (!A.repo.owner || !A.repo.token) return toast('先在第二节把仓库和令牌填好');

  const hours = Number($('ttl').value);
  const exp = Math.floor(Date.now() / 1000) + hours * 3600;
  const bytes = I.packInvite({
    kind: I.KIND_ADMIN,
    nonce: C.randHex(8),
    exp: exp,
    dh: k.dh, sig: k.sig,
    uid: p.uid, name: p.name,
    repo: A.repo
  });

  const url = I.inviteToUrl(location.origin + location.pathname.replace(/admin\.html$/, ''), bytes);
  const q = qrSvg(C.utf8(url), { ecl: 1 });

  $('invWho').textContent = p.name + ' 的邀请码';
  $('invMeta').textContent = bytes.length + ' 字节 · 二维码版本 ' + q.ver + '（' + q.size + '×' + q.size +
    ' 模块，' + q.px + 'px）· 离屏幕 20–30 厘米扫 · ' + fmtTime(exp * 1000) + ' 过期 · 只能领一次';
  $('invQr').innerHTML = q.svg;
  $('invText').value = I.inviteToText(bytes);
  $('invText').dataset.uid = p.uid;
  $('inv').hidden = false;
}

$('btnInvClose').onclick = () => { $('inv').hidden = true; };
$('btnInvCopy').onclick = () => copy($('invText').value);
$('btnInvSave').onclick = () => download('invite-' + ($('invText').dataset.uid || 'x') + '.txt', $('invText').value);

$('btnWipeKeys').onclick = () => {
  if (!confirm('清除本机保存的全部成员私钥？此后无法再给现有成员发码，只能重发新钥匙。')) return;
  A.keys = {};
  save(); renderPeople(); toast('清干净了');
};

/* ------------------------------------------------------------ 领取状态 */

async function loadClaims() {
  if (!A.repo.owner || !A.repo.token) return toast('先填仓库和令牌');
  CLAIMS = {};
  for (const p of A.people) {
    try {
      const c = await S.readJson(A.repo, 'claims/' + p.uid + '.json');
      if (c) CLAIMS[p.uid] = c;
    } catch (e) { /* 单个读不到不影响别人 */ }
  }
  renderPeople();
  toast('领取状态已刷新');
}

async function resetClaim(p) {
  if (!confirm('重置 ' + p.name + ' 的领取记录？他已登记的设备会从名单里消失，' +
               '旧的邀请码也会重新变得可用——除非你同时发一张新码。')) return;
  try {
    await S.transact(A.repo, () => ({
      message: '重置 ' + p.uid + ' 的领取记录',
      dels: ['claims/' + p.uid + '.json']
    }));
    delete CLAIMS[p.uid];
    renderPeople();
    toast('已重置');
  } catch (e) { toast('重置失败：' + e.message, 4000); }
}

$('btnClaims').onclick = loadClaims;

/* ----------------------------------------------------------- 花名册 */

/* 签的是这一串字符串本身，不是重新序列化的对象——避免验签端因键顺序或
   空白差异莫名其妙地失败。 */
async function buildRoster() {
  if (!A.admin) throw new Error('先生成管理员钥匙');
  if (!A.people.length) throw new Error('花名册里一个人都没有');
  const body = JSON.stringify({
    v: 1, ts: Date.now(),
    people: A.people.map((p) => ({ uid: p.uid, name: p.name, groups: p.groups || [], dh: p.dh, sig: p.sig }))
  });
  const priv = await C.importSigPriv(A.admin.jwk);
  return JSON.stringify({ body, sig: await C.signRoster(body, priv) }, null, 1);
}

$('btnSign').onclick = async () => {
  try { $('rosterOut').value = await buildRoster(); say('签好了。', 'ok'); }
  catch (e) { say(e.message, 'err'); }
};

$('btnDownload').onclick = async () => {
  try { download('roster.json', await buildRoster()); }
  catch (e) { say(e.message, 'err'); }
};

$('btnPush').onclick = async () => {
  try {
    if (!A.repo.token) throw new Error('先填仓库和令牌');
    const text = await buildRoster();
    $('rosterOut').value = text;
    say('正在写入仓库…');
    await S.transact(A.repo, () => ({
      message: '更新花名册（' + A.people.length + ' 人）',
      puts: [{ path: 'roster.json', b64: C.b64(C.utf8(text)) }]
    }));
    say('已写入 ' + A.repo.owner + '/' + A.repo.repo + '。', 'ok');
  } catch (e) { say('写入失败：' + e.message, 'err'); }
};

/* 从仓库拉回来，方便换机器后接着改组（公钥全在里面，私钥本来就不该在） */
$('btnLoad').onclick = async () => {
  try {
    if (!A.repo.token) throw new Error('先填仓库和令牌');
    const raw = await S.readJson(A.repo, 'roster.json');
    if (!raw || !raw.body) throw new Error('仓库里没有 roster.json');
    const body = JSON.parse(raw.body);
    const known = {};
    for (const p of A.people) known[p.uid] = p;
    A.people = body.people.map((p) => Object.assign({}, known[p.uid] || {}, p));
    save(); renderPeople();
    say('拉回 ' + A.people.length + ' 人。', 'ok');
  } catch (e) { say(e.message, 'err'); }
};

renderAdmin();
renderPeople();
