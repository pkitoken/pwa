/* Daily Brief — offline PWA reader.
 *
 * Security model:
 *   - This file is public. It contains NO key material of any kind.
 *   - The RSA private key is imported once by the user from a local file,
 *     wrapped with a passphrase (PBKDF2-SHA256, 600k iterations) and kept in
 *     IndexedDB. It never touches the network.
 *   - After a successful unlock the unwrapped key is cached for 24 hours,
 *     then purged and the passphrase is required again.
 */
const APP_VERSION = "6.3";
const API = "/ipa";            // 仅路径叫 ipa，其余一律 api
const LANDSCAPE_ZOOM = 1.28;   // 横屏整体放大倍数，想调就改这里
const POLL_MS = 3000;          // 结果轮询间隔
const MAX_WAIT_MS = 240000;    // 最长等 4 分钟
const REMEMBER_MS = 24 * 60 * 60 * 1000;
const PBKDF2_ITERS = 600000;

const $ = (id) => document.getElementById(id);
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------- IndexedDB ---------- */
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("brief", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function kvGet(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const r = db.transaction("kv").objectStore("kv").get(k);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function kvSet(k, v) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readwrite");
    t.objectStore("kv").put(v, k);
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
  });
}
async function kvDel(k) {
  const db = await idb();
  return new Promise((res) => {
    const t = db.transaction("kv", "readwrite");
    t.objectStore("kv").delete(k);
    t.oncomplete = () => res();
  });
}

/* ---------- passphrase wrapping ---------- */
async function deriveWrapKey(pass, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function storeKey(pkcs8, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wk = await deriveWrapKey(pass, salt);
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wk, pkcs8);
  await kvSet("wrapped", { salt: b64e(salt), iv: b64e(iv), data: b64e(wrapped) });
  await kvDel("session");
}

async function unwrapKey(pass) {
  const rec = await kvGet("wrapped");
  if (!rec) throw new Error("尚未导入私钥");
  const wk = await deriveWrapKey(pass, b64d(rec.salt));
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(rec.iv) }, wk, b64d(rec.data));
  } catch { throw new Error("口令错误"); }
  await kvSet("session", { pkcs8: b64e(pkcs8), exp: Date.now() + REMEMBER_MS });
  return importPriv(pkcs8);
}

function importPriv(pkcs8) {
  return crypto.subtle.importKey("pkcs8", pkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function sessionKey() {
  const s = await kvGet("session");
  if (!s) return null;
  if (Date.now() > s.exp) { await kvDel("session"); return null; }
  return importPriv(b64d(s.pkcs8));
}

/* ---------- 多源取数 ----------
 * 旧注释写着「raw.githubusercontent is blocked in CN」—— 2026-08-14 从上海移动
 * 实测已不成立（raw / Pages / api.github.com 全部可达）。封锁状态会来回变，
 * 所以不再假设哪个通，改成并发发出、谁先回用谁。见下方 fetchPayload()。 */
const MARKETS = { us: "🇺🇸 美股", cn: "🇨🇳 中港股" };
// 与 code/ticker_report.py 的 resolve() 规则一致：市场由代码格式决定，不由用户选
function tickerMarket(t) {
  const c = String(t).trim().toUpperCase();
  if (/\.HK$/.test(c)) return "cn";
  if (/\.(SS|SZ)$/.test(c)) return "cn";
  if (/^\d{4,6}$/.test(c)) return "cn";
  if (/^[A-Z.\-]{1,6}$/.test(c)) return "us";
  return null;
}

const HIST_MAX = 5;
const HIST_TTL = 48 * 3600 * 1000;        // 与 OCI 的结果保留期一致

async function histGet() {
  const h = ((await kvGet("history")) || []).map((x) =>
    x.ts && x.ts < 1e11 ? { ...x, ts: x.ts * 1000 } : x);   // 兼容早期写入的秒级时间戳
  const live = h.filter((x) => Date.now() - x.ts < HIST_TTL);
  if (live.length !== h.length) await kvSet("history", live);
  return live;
}
async function histMark(id, done) {
  const h = await histGet();
  const i = h.findIndex((x) => x.id === id);
  if (i >= 0 && h[i].done !== done) { h[i].done = done; await kvSet("history", h); }
}
async function histAdd(rec) {
  const h = await histGet();
  await kvSet("history", [rec, ...h.filter((x) => x.id !== rec.id)].slice(0, HIST_MAX));
}
function ago(ts) {
  const m = Math.round((Date.now() - ts) / 60000);
  if (m < 1) return "刚刚";
  if (m < 60) return `${m} 分钟前`;
  const hr = Math.round(m / 60);
  return hr < 24 ? `${hr} 小时前` : `${Math.round(hr / 24)} 天前`;
}
async function rebuildMarketSelect(keep) {
  const sel = $("market");
  const cur = keep || sel.value;
  sel.innerHTML = "";
  for (const [k, v] of Object.entries(MARKETS))
    sel.add(new Option(v, k));
  const h = await histGet();
  if (h.length) {
    const g = document.createElement("optgroup");
    g.label = "按需分析（48 小时内）";
    for (const x of h) g.appendChild(new Option(`📊 ${x.label} · ${ago(x.ts)}`, "job:" + x.id));
    sel.appendChild(g);
  }
  if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
}
const file = (m) => `brief-${m}.json`;

/* GitHub 上的第二个下载地址。**同一次 push 产生的同一个文件**，
 * 只是走不同的域名 —— 因为「今天通、明天不通」是这套系统的常态：
 * 2026-08-14 实测上海移动 raw 与 Pages 都通，而更早的注释记录着 raw 曾被封。
 * 两个一起发、谁先回用谁，任意一边被封都不用改代码、不用等超时。 */
const GH_USER = "pkitoken", GH_PWA_REPO = "pwa", GH_PWA_DIR = "brief";
const rawURL = (f) =>
  `https://raw.githubusercontent.com/${GH_USER}/${GH_PWA_REPO}/main/${GH_PWA_DIR}/${f}`;

const SOURCES = (m) => [
  { label: "本站", url: `./${file(m)}?t=${Date.now()}` },
  { label: "raw", url: `${rawURL(file(m))}?t=${Date.now()}` },
];

async function one(s) {
  const r = await fetch(s.url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${s.label}: HTTP ${r.status}`);
  const p = await r.json();
  if (!p || !p.ct) throw new Error(`${s.label}: 格式无效`);
  return { payload: p, src: s.label, cached: false };
}

async function fetchPayload(m) {
  /* Promise.any：并发发出，第一个**成功**的胜出，失败的被忽略。
   * 不是 Promise.race —— race 会让先返回的「失败」直接判负。
   *
   * ⚠️ 两个源理论上可能不同代（一边 push 成功另一边失败）。
   * 不做版本比对是有意的：那要等两边都回来，等于放弃了并发的全部收益。
   * 界面本来就显示简报时间，真出现落后一代你会直接看到「N 小时前」。 */
  try {
    const win = await Promise.any(SOURCES(m).map(one));
    await kvSet("cache-" + m, win.payload);   // 离线兜底，别删
    return win;
  } catch (agg) {
    const errs = (agg.errors || []).map((e) => e.message);
    const c = await kvGet("cache-" + m);
    if (c) return { payload: c, src: "本地缓存", cached: true, errs };
    throw new Error(`${MARKETS[m]} 全部源不可达，且无缓存\n` + errs.join("\n"));
  }
}

/* ---------- 本地个股报告缓存 ----------
 * 存密文不存明文：手机上已有口令包裹的私钥，再存明文报告等于降级。
 * 解密只花几十毫秒，换取「解锁一次不等于全部暴露」。 */
const REPORT_MAX = 20;
const REPORT_TTL = 48 * 3600 * 1000;

function mktOpen(mkt) {
  const now = new Date();
  const tz = mkt === "us" ? "America/New_York" : "Asia/Shanghai";
  const p = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour12: false,
    weekday: "short", hour: "2-digit", minute: "2-digit" }).formatToParts(now);
  const g = (t) => p.find((x) => x.type === t).value;
  if (["Sat", "Sun"].includes(g("weekday"))) return false;
  const h = +g("hour") + +g("minute") / 60;
  return mkt === "us" ? (h >= 9.5 && h < 16)
                      : ((h >= 9.5 && h < 11.5) || (h >= 13 && h < 15.99));
}
const reportTTL = (mkt) => (mktOpen(mkt) ? 5 * 60000 : 12 * 3600000);

async function reportGet(mkt, tk) {
  const all = (await kvGet("reports")) || {};
  const r = all[`${mkt}:${tk}`];
  if (!r) return null;
  const age = Date.now() - r.ts;
  if (age > REPORT_TTL) return null;
  return { ...r, age, fresh: age < reportTTL(mkt) };
}
async function reportPut(mkt, tk, payload, name) {
  const all = (await kvGet("reports")) || {};
  all[`${mkt}:${tk}`] = { ts: Date.now(), payload, tk, mkt, name: name || "" };
  const keys = Object.keys(all).sort((a, b) => all[b].ts - all[a].ts);
  const keep = {};
  for (const k of keys.slice(0, REPORT_MAX))
    if (Date.now() - all[k].ts < REPORT_TTL) keep[k] = all[k];
  await kvSet("reports", keep);
}

/* ---------- 签名（同一把私钥，换算法再导入一次用于签名） ---------- */
async function signKey() {
  const s = await kvGet("session");
  if (!s) throw new Error("未解锁");
  if (Date.now() > s.exp) { await kvDel("session"); throw new Error("已超时，请重新解锁"); }
  return crypto.subtle.importKey("pkcs8", b64d(s.pkcs8),
    { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]);
}

async function signedPost(body) {
  const key = await signKey();
  const raw = enc.encode(JSON.stringify(body));
  const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, raw);
  return fetch(`${API}/request`, {
    method: "POST", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-Signature": b64e(sig) },
    body: raw,
  });
}

async function apiStatus() {
  const r = await fetch(`${API}/status?t=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

/* ================= GitHub 收件箱通道 =================
 *
 * Pages 上没有后端（`/ipa` 是 OCI 才有的），所以按需分析改走「指令文件」：
 * 手机把指令**加密**后写进私有仓库，本机每 5 分钟取一次、跑完把结果写回来。
 *
 * 时间尺度和 OCI 完全不同 —— OCI 是几十秒，这里是**十几到三十分钟**
 * （轮询 ≤5 分钟 + AI 跑 5–20 分钟 + 推送）。所以下面的超时与轮询间隔
 * 必须按通道分别取值，否则会在结果出现之前就判定失败。
 */
const IS_GH = /\.github\.io$/i.test(location.hostname);
const GH_INBOX = "daily-brief";          // 收件箱仓库（私有，无 Pages）
const GH_API = "https://api.github.com";

const waitMs = () => (IS_GH ? 45 * 60000 : MAX_WAIT_MS);
// GitHub API 认证后 5000 次/小时；15 秒一次 = 240 次/小时，很安全
const pollMs = () => (IS_GH ? 15000 : POLL_MS);

/* 令牌来源有两条，优先本地手工粘贴的：
 *   1. IndexedDB 里手工粘贴的（覆盖用，一般不需要）
 *   2. inbox-token.json —— 本机用公钥#1 加密下发的，**所有设备自动共享**
 *
 * 走第 2 条时令牌被**口令 + 私钥#1** 保护；手工粘贴那份在 IndexedDB 里是
 * 明文的，拿到手机不用口令就能读出来。所以第 2 条其实更安全。
 *
 * 只在内存里缓存：页面一关就没了，令牌不会静默沉淀到磁盘上。 */
let _tok = null;
async function ghTok() {
  const local = await kvGet("ghtoken");
  if (local) return local;
  if (_tok) return _tok;
  const priv = await sessionKey();
  if (!priv) return null;                    // 没解锁就拿不到令牌，这是有意的
  try {
    const get = (u) => fetch(u, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))));
    const p = await Promise.any([
      get(`./inbox-token.json?t=${Date.now()}`),
      get(`${rawURL("inbox-token.json")}?t=${Date.now()}`),
    ]);
    _tok = (await decryptPayload(p, priv)).trim();
    return _tok;
  } catch { return null; }                   // 本机没配令牌 → 走手工粘贴那条
}

/* 设备标识：**不做浏览器指纹**。UA/分辨率会撞车也会漂移，拿它当唯一标识
 * 不可靠。直接发一个随机 UUID 更准，也更干净。
 * ⚠️ 它标识的是「一次安装」——清除浏览器数据或重装后会变成新设备。 */
async function device() {
  let d = await kvGet("device");
  if (!d || !d.id) {
    d = { id: crypto.randomUUID(), name: (d && d.name) || "" };
    await kvSet("device", d);
  }
  return d;
}

/* 文件名用**北京时间** MMDDHHmm，与本机 instruction_runner.py 的命名一致 */
function stamp() {
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai",
    hour12: false, month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit" }).formatToParts(new Date());
  const g = (t) => p.find((x) => x.type === t).value;
  return `${g("month")}${g("day")}${g("hour")}${g("minute")}`;
}

/* 取当前会话密钥 K：拉那 800 字节的 inbox-key.json，用私钥#1 解开。
 * **每次提交前都重新拉**，不依赖 App 启动时那一次 —— App 可能已经开了
 * 几小时，手里的 kid 早就旧了。本机 keyring 留 5 把只是安全网。 */
async function inboxKey() {
  const priv = await sessionKey();
  if (!priv) throw new Error("未解锁");
  const get = (u) => fetch(u, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))));
  const man = await Promise.any([
    get(`./inbox-key.json?t=${Date.now()}`),
    get(`${rawURL("inbox-key.json")}?t=${Date.now()}`),
  ]);
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b64d(man.inbox_key));
  return { kid: man.kid,
           k: await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]) };
}

async function ghFetch(path, opts = {}) {
  const tok = await ghTok();
  if (!tok) throw new Error("尚未设置 GitHub 令牌（按需面板底部 ⚙）");
  /* ⚠️ path 为空时**不能留下尾斜杠**：`/repos/o/r/` 在 GitHub 上是 404，
   * 而 CORS 预检必须返回 2xx 才算通过 —— 404 的预检直接失败，浏览器抛出
   * `TypeError: Failed to fetch`，**看不到那个 404**，排查时极易误判成网络问题。
   * （2026-08-14 手机上就是这么炸的。） */
  const base = `${GH_API}/repos/${GH_USER}/${GH_INBOX}`;
  return fetch(path ? `${base}/${path}` : base, {
    ...opts, cache: "no-store",
    headers: { Authorization: `Bearer ${tok}`,
               Accept: "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", ...(opts.headers || {}) },
  });
}

async function ghSubmit(body) {
  const { kid, k } = await inboxKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  /* 设备信息放在**密文里面**。放外层等于把「有几台设备、什么时候提交、
   * 关心哪些票」公开出去 —— 外层只留 kid，它是随机字节，不泄露任何东西。 */
  const plain = enc.encode(JSON.stringify(
    { ...body, device: await device(), ts: new Date().toISOString() }));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, plain);
  const env = JSON.stringify({ v: 1, kid, iv: b64e(iv), ct: b64e(ct) });

  // 同一分钟内提交两次会撞名（命名精度只到分钟），撞了就加后缀重试
  const base = stamp();
  for (const sfx of ["", "b", "c", "d"]) {
    const id = base + sfx;
    const r = await ghFetch(`contents/${encodeURIComponent("AI指令-" + id + ".json")}`, {
      method: "PUT",
      body: JSON.stringify({ message: `指令 ${id}`, content: b64e(enc.encode(env)) }),
    });
    if (r.ok) return { ok: true, status: 200, json: async () => ({ id }) };
    if (r.status !== 422) {                       // 422 = 文件已存在
      const j = await r.json().catch(() => ({}));
      throw new Error(j.message || `HTTP ${r.status}`);
    }
  }
  throw new Error("同一分钟内提交过多，稍后再试");
}

async function ghResult(id) {
  let r;
  try {
    r = await ghFetch(`contents/${encodeURIComponent("回复AI指令-" + id + ".json")}`,
                      { headers: { Accept: "application/vnd.github.raw+json" } });
  } catch (e) {
    return { ok: false, status: 0, json: async () => ({ error: e.message }) };
  }
  // 还没写回来 —— 用 202 表达「在跑」，与 OCI 端语义对齐，上层不必分支
  if (r.status === 404) return { ok: false, status: 202, json: async () => ({}) };
  if (!r.ok) return { ok: false, status: r.status, json: async () => ({}) };
  const p = await r.json();
  return { ok: true, status: 200, json: async () => p };
}

/* 两个通道的统一入口。上层调用处不需要知道自己跑在哪里。 */
const apiPost = (body) => (IS_GH ? ghSubmit(body) : signedPost(body));
const apiResult = (id) => (IS_GH ? ghResult(id)
  : fetch(`${API}/result/${id}?t=${Date.now()}`, { cache: "no-store" }));

/* ---------- decrypt ---------- */
async function decryptPayload(p, priv) {
  const aesRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b64d(p.ek));
  const aes = await crypto.subtle.importKey("raw", aesRaw, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(p.iv) }, aes, b64d(p.ct));
  return dec.decode(plain);
}

/* ---------- UI ---------- */
function show(view) {
  ["setup", "unlock", "content"].forEach((v) => $(v).hidden = v !== view);
  if (view !== "content") { $("chips").hidden = true; $("chips").innerHTML = ""; }
}
function status(msg, bad) {
  const s = $("status");
  s.textContent = msg || "";
  s.className = bad ? "bad" : "";
}

async function render() {
  const v = $("market").value;
  await kvSet("lastMarket", v);

  if (v.startsWith("job:")) return renderJob(v.slice(4));

  currentTicker = null;                    // 切回简报，清掉上下文
  status(`正在获取 ${MARKETS[v]}…`);
  let res;
  try { res = await fetchPayload(v); }
  catch (e) { status(e.message, true); return; }

  const priv = await sessionKey();
  if (!priv) { show("unlock"); status(""); return; }

  try {
    const brief = await decryptPayload(res.payload, priv);
    $("frame").style.height = "60vh";                     // 先给个临时高度，等脚本报回真实值
    delete $("frame").dataset.zoomed;
    $("frame").srcdoc = injectClicks(brief);
    show("content");
    await buildChipsFrom(brief, v);
    const tz = res.payload.tz === "Asia/Shanghai" ? "北京时间" : "纽约时间";
    const age = res.payload.ts ? new Date(res.payload.ts).toLocaleString("zh-CN") : "未知";
    status(`${res.cached ? "⚠ 离线，" : ""}${MARKETS[v]} · ${age} ${tz} · v${APP_VERSION}`, res.cached);
  } catch (e) {
    status("解密失败——私钥不匹配？" + e.message, true);
    show("unlock");
  }
}

/* 取回一份按需分析。还在跑就接着显示进度，跑完就渲染。 */
async function renderJob(id) {
  const h = await histGet();
  const rec = h.find((x) => x.id === id);
  const label = rec ? rec.label : id;
  const priv = await sessionKey();
  if (!priv) { show("unlock"); status(""); return; }

  status(`正在取回 ${label}…`);
  let r;
  try { r = await apiResult(id); }
  catch (e) { status("网络不可达：" + e.message, true); return; }

  if (r.status === 202) { pollJob(id, rec, null); return; }     // 还在跑，交给后台轮询
  if (r.status === 404) { status(`${label} 的结果已过期（保留 48 小时）`, true); return; }
  if (!r.ok) { status("取回失败：HTTP " + r.status, true); return; }

  const p = await r.json();
  await histMark(id, true);
  if (p.error) { status(`${label} 执行失败：${p.error}`, true); return; }
  await showResult(p, label, null);
}

/* import key file */
$("keyfile").addEventListener("change", async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const pass = $("newpass").value;
  if (pass.length < 8) { status("口令至少 8 位", true); return; }
  try {
    let buf = await f.arrayBuffer();
    const head = dec.decode(new Uint8Array(buf.slice(0, 40)));
    if (head.includes("-----BEGIN")) {            // PEM -> DER
      const pem = dec.decode(new Uint8Array(buf));
      const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
      buf = b64d(body).buffer;
    }
    await importPriv(buf);                        // validate before storing
    await storeKey(buf, pass);
    $("newpass").value = "";
    status("私钥已导入");
    show("unlock");
  } catch (e) {
    status("导入失败：" + e.message + "（请确认选的是 private-pkcs8.der）", true);
  }
});

$("unlockbtn").addEventListener("click", async () => {
  try {
    await unwrapKey($("pass").value);
    $("pass").value = "";
    await render();
  } catch (e) { status(e.message, true); }
});
$("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("unlockbtn").click(); });
/* ---------- 按需运行 ---------- */
function jobType() {
  return document.querySelector('input[name=job]:checked').value;
}

async function refreshModal(note) {
  if (note) $("note").textContent = note; else $("note").textContent = "";
  $("hoststat").textContent = "正在检查本机状态…";
  $("hoststat").className = "hint";
  $("submit").disabled = true;
  $("toghset").hidden = !IS_GH;

  if (IS_GH) return refreshModalGH();

  try {
    const st = await apiStatus();
    const q = st.quota[$("reqmarket").value];
    $("quota").textContent = `今日剩余 ${q.left} / ${q.limit} 次（缓存命中不计数）`;
    if (!st.host_alive) {
      const mins = st.host_seen ? Math.round((st.now - st.host_seen) / 60) : null;
      $("hoststat").textContent = mins === null
        ? "⚠ 本机从未上线，无法执行" : `⚠ 本机离线（最后在线 ${mins} 分钟前），无法执行`;
      $("hoststat").className = "hint bad";
    } else if (st.busy) {
      $("hoststat").textContent = "⚠ 本机正忙，请稍后再试";
      $("hoststat").className = "hint bad";
    } else if (q.left <= 0) {
      $("hoststat").textContent = "⚠ 今日配额已用尽";
      $("hoststat").className = "hint bad";
    } else {
      $("hoststat").textContent = "✅ 本机在线，可以执行";
      $("submit").disabled = false;
    }
  } catch (e) {
    $("hoststat").textContent = "⚠ 无法连接服务：" + e.message;
    $("hoststat").className = "hint bad";
  }
}

/* GitHub 通道没有 /ipa/status。这里能验证的是「令牌是否有效、收件箱是否可写」，
 * **验证不了本机是否在跑** —— 指令是异步的，本机可能几分钟后才来取。
 * 所以文案不要写「本机在线」，那是 OCI 通道才能给的保证。 */
async function refreshModalGH() {
  $("quota").textContent = "";
  const tok = await ghTok();
  if (!tok) {
    $("hoststat").textContent = "⚠ 拿不到 GitHub 令牌 —— 本机尚未下发，可点 ⚙ 手工填";
    $("hoststat").className = "hint bad";
    return;
  }
  try {
    const r = await ghFetch("");
    if (r.status === 401) throw new Error("令牌无效或已过期");
    if (r.status === 404) throw new Error(`看不到 ${GH_INBOX} 仓库（令牌权限不足？）`);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    if (!j.permissions || !j.permissions.push) throw new Error("令牌没有写权限");
    $("hoststat").innerHTML = "✅ 收件箱可写 · 指令将在几分钟内被取走"
      + '<br><span style="opacity:.7">本机每 5 分钟取一次，出报告约 10–30 分钟</span>';
    $("hoststat").className = "hint";
    $("submit").disabled = false;
  } catch (e) {
    $("hoststat").textContent = "⚠ " + e.message;
    $("hoststat").className = "hint bad";
  }
}

/* ---------- GitHub 设置面板 ---------- */
$("toghset").addEventListener("click", async () => {
  const d = await device();
  $("ghdev").value = d.name || "";
  $("ghtoken").value = "";
  const auto = !(await kvGet("ghtoken")) && !!(await ghTok());
  $("ghstat").textContent = auto
    ? "✅ 已自动取得本机下发的令牌 —— 无需填写。填了则以你填的为准。"
    : ((await kvGet("ghtoken")) ? "已存有手工填写的令牌（留空则不改动）" : "");
  $("ghset").hidden = false;
});
$("ghclose").addEventListener("click", () => { $("ghset").hidden = true; });
$("ghset").addEventListener("click", (e) => { if (e.target.id === "ghset") $("ghset").hidden = true; });
$("ghsave").addEventListener("click", async () => {
  const t = $("ghtoken").value.trim();
  if (t) await kvSet("ghtoken", t);
  const d = await device();
  await kvSet("device", { ...d, name: $("ghdev").value.trim() });
  $("ghtoken").value = "";
  $("ghset").hidden = true;
  refreshModal();
});
$("ghforget").addEventListener("click", async () => {
  await kvDel("ghtoken");
  _tok = null;                               // 内存缓存一并清掉
  $("ghstat").textContent = "已清除";
  refreshModal();
});

$("ondemand").addEventListener("click", async () => {
  if (!(await kvGet("session"))) { status("请先解锁", true); return; }
  openModal(currentTicker
    ? { ticker: currentTicker,
        note: `当前正在看 ${tickerNames[currentTicker] || currentTicker}，可直接重新分析` }
    : {});
});
$("cancel").addEventListener("click", () => { $("modal").hidden = true; });
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("modal").hidden = true; });
$("reqmarket").addEventListener("change", refreshModal);
function syncMarketLock() {
  const jt = jobType();
  const isTk = jt === "ticker";
  $("tickerbox").hidden = !isTk;
  $("freebox").hidden = jt !== "free";
  const tk = $("ticker").value.trim().toUpperCase();
  $("tomgmt").hidden = !(isTk && tk);
  const sel = $("reqmarket");
  if (jt === "lhb") {
    // 龙虎榜是 A 股独有的制度，港股没有，美股无关
    sel.disabled = true;
    sel.value = "cn";
    $("mkthint").textContent = "龙虎榜是 A 股制度，港股无此披露";
    return;
  }
  if (isTk) {
    const m = tickerMarket($("ticker").value);
    sel.disabled = true;
    if (m) sel.value = m;
    $("mkthint").textContent = m ? `市场由代码自动判定：${MARKETS[m]}`
                                 : "输入代码后自动判定市场";
  } else {
    sel.disabled = false;
    $("mkthint").textContent = "";
  }
}
document.querySelectorAll('input[name=job]').forEach((r) =>
  r.addEventListener("change", syncMarketLock));
$("ticker").addEventListener("input", () => { syncMarketLock(); refreshModal(); });

$("submit").addEventListener("click", async () => {
  const job = jobType();
  const body = { job, market: $("reqmarket").value,
                 ai: $("withai").checked, ts: Math.floor(Date.now() / 1000) };
  if (job === "free") {
    const t = $("freetext").value.trim();
    if (t.length < 4) { $("hoststat").textContent = "⚠ 指令内容太短"; $("hoststat").className = "hint bad"; return; }
    if (!IS_GH) { $("hoststat").textContent = "⚠ 自由指令只在 GitHub 通道可用"; $("hoststat").className = "hint bad"; return; }
    body.text = t;
  } else if (job === "lhb") {
    body.market = "cn";                   // 龙虎榜只有 A 股有，OCI 端也会挡
  } else if (job === "ticker") {
    const t = $("ticker").value.trim().toUpperCase();
    if (!/^[A-Z0-9][A-Z0-9.\-]{0,11}$/.test(t)) { $("hoststat").textContent = "⚠ 代码格式不合法"; $("hoststat").className = "hint bad"; return; }
    const m = tickerMarket(t);
    if (!m) { $("hoststat").textContent = "⚠ 无法识别该代码属于哪个市场"; $("hoststat").className = "hint bad"; return; }
    body.ticker = t;
    body.market = m;                      // 市场由代码决定，配额也记到正确的市场
  }
  $("submit").disabled = true;
  try {
    const r = await apiPost(body);
    const j = await r.json();
    if (!r.ok) { $("hoststat").textContent = "⚠ " + (j.error || r.status); $("hoststat").className = "hint bad"; $("submit").disabled = false; return; }
    $("modal").hidden = true;
    const label = body.job === "ticker" ? body.ticker
                : body.job === "free" ? (body.text.slice(0, 12) + (body.text.length > 12 ? "…" : ""))
                : body.job === "lhb" ? "龙虎榜"
                : (body.market === "us" ? "美股简报" : "中港简报");
    // 注意顺序：body.ts 是「秒」，必须放在前面，否则会盖掉毫秒时间戳
    const rec = { ...body, id: j.id, label, ts: Date.now() };
    await histAdd(rec);
    await rebuildMarketSelect("job:" + j.id);
    pollJob(j.id, rec, j.left);
  } catch (e) {
    $("hoststat").textContent = "⚠ " + e.message; $("hoststat").className = "hint bad"; $("submit").disabled = false;
  }
});

/* ---------- 简报里的代码可点 ----------
 * 生成端已把代码包成 <span tk data-tk=… data-mkt=…>，父页面直接在
 * iframe 文档上挂监听 —— 不需要给 iframe 加 allow-scripts，沙箱不削弱。 */
/* 注入到简报里的点击转发脚本。
 * iframe 沙箱是 allow-scripts 但**没有** allow-same-origin —— 脚本跑在独立源，
 * 读不到父页面的 IndexedDB（也就是私钥）。父页面直接挂监听在 iOS Safari 上不触发，
 * postMessage 则各平台一致。 */
const CLICK_JS =
  "<scr" + "ipt>" +
  "document.addEventListener('click',function(e){" +
  "var el=e.target.closest&&e.target.closest('[data-tk]');if(!el)return;" +
  "e.preventDefault();parent.postMessage({t:'tk',tk:el.getAttribute('data-tk')," +
  "mkt:el.getAttribute('data-mkt'),nm:el.getAttribute('data-nm')||''},'*');});" +
  // 把内容高度报给父页面 —— 父页面据此撑开 iframe，让整页滚动而不是 iframe 内滚，
  // 这样双指缩放才是正常的「放大网页」体验
  "function H(){var w=document.body.__w,h;" +
  "if(w){h=w.getBoundingClientRect().height;}" +          // transform 后的实际高度
  "else{h=Math.max(document.documentElement.scrollHeight,document.body.scrollHeight);}" +
  "parent.postMessage({t:'h',h:Math.ceil(h)+8},'*');}" +
  // iframe 内的 orientation 媒体查询按 iframe 自身尺寸算（内容很高 = 永远「竖」），
  // 所以放大倍数必须由父页面下发
  // 用 transform:scale 而非 zoom —— Safari 对 zoom 支持不稳定。
  // 把包裹层宽度设为 100/z%，再放大 z 倍，视觉等同 zoom：内容按新宽度重排，不横向溢出。
  "function W(){var b=document.body;if(!b.__w){var w=document.createElement('div');" +
  "while(b.firstChild)w.appendChild(b.firstChild);b.appendChild(w);b.__w=w;}return b.__w;}" +
  "function Z(z){var w=W();if(z===1){w.removeAttribute('style');}else{" +
  "w.style.transformOrigin='top left';w.style.width=(100/z)+'%';" +
  "w.style.transform='scale('+z+')';}setTimeout(H,50);setTimeout(H,300);}" +
  "addEventListener('message',function(e){var d=e.data;if(!d||d.t!=='zoom')return;Z(d.z);});" +
  "addEventListener('load',H);addEventListener('resize',H);" +
  "setTimeout(H,60);setTimeout(H,400);setTimeout(H,1200);" +
  "if(window.ResizeObserver)new ResizeObserver(H).observe(document.documentElement);" +
  "</scr" + "ipt>";

/* 横屏放大：用 zoom 而非改字号 —— 内容会按新宽度重新排版，不会横向溢出。
   同时关掉 iOS Safari 的自动文本放大，让两个平台表现一致。 */
const ZOOM_CSS =
  "<style>html{-webkit-text-size-adjust:100%;text-size-adjust:100%}</style>";

function injectClicks(html) {
  const add = ZOOM_CSS + CLICK_JS;
  return html.includes("</body>") ? html.replace("</body>", add + "</body>")
                                  : html + add;
}

/* 代码条：直接解析 HTML 字符串取标的，不依赖 iframe DOM（已无同源权限） */
async function buildChipsFrom(html, mkt) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const seen = new Map();
  doc.querySelectorAll("[data-tk]").forEach((el) => {
    const tk = el.getAttribute("data-tk");
    if (tk && !seen.has(tk))
      seen.set(tk, [el.getAttribute("data-mkt"), el.getAttribute("data-nm") || ""]);
  });
  // 本地研究过但简报里还没有的标的 —— 主机端已加入自选，下次简报才会带上，
  // 这里先补进来，点完就能马上再点。
  // **必须按市场过滤**：否则在中港简报里会冒出美股标的（本地缓存是跨市场的）。
  // 市场以代码格式重新推导，顺带纠正早期版本可能写错的 r.mkt。
  const rep = (await kvGet("reports")) || {};
  for (const r of Object.values(rep)) {
    if (!r.tk || seen.has(r.tk)) continue;
    if (r.tk === "LHB") continue;          // 龙虎榜是全榜，不是标的，别混进代码条
    const m = tickerMarket(r.tk) || r.mkt;
    if (mkt && m !== mkt) continue;
    seen.set(r.tk, [m, r.name || "", true]);
  }
  const bar = $("chips");
  bar.innerHTML = "";
  for (const [tk, [mkt, nm, isNew]] of seen) {
    const b = document.createElement("button");
    b.className = "chip" + (isNew ? " chip-new" : "");
    b.textContent = tk;
    b.title = nm || tk;
    if (nm) tickerNames[tk] = nm;
    b.addEventListener("click", () => onTicker(tk, mkt, nm));
    bar.appendChild(b);
  }
  bar.hidden = seen.size === 0;
}

function wantZoom() {
  return matchMedia("(orientation: landscape)").matches ? LANDSCAPE_ZOOM : 1;
}
function pushZoom() {
  const w = $("frame").contentWindow;
  if (w) w.postMessage({ t: "zoom", z: wantZoom() }, "*");
}
// 转屏与窗口尺寸变化都重新下发
matchMedia("(orientation: landscape)").addEventListener?.("change", pushZoom);
window.addEventListener("orientationchange", () => setTimeout(pushZoom, 60));
window.addEventListener("resize", () => { clearTimeout(window.__zt);
  window.__zt = setTimeout(pushZoom, 150); });

window.addEventListener("message", (e) => {
  if (e.source !== $("frame").contentWindow) return;      // 只认自己那个 iframe
  const d = e.data;
  if (!d) return;
  if (d.t === "tk") onTicker(d.tk, d.mkt, d.nm);
  else if (d.t === "h" && d.h > 0) {
    $("frame").style.height = Math.ceil(d.h) + "px";
    if (!$("frame").dataset.zoomed) { $("frame").dataset.zoomed = "1"; pushZoom(); }
  }
});

/* 兜底：父页面里的原生按钮，无论 iframe 内的监听是否生效都能点。 */
function buildChips(pairs) {
  const bar = $("chips");
  const seen = new Set();
  bar.innerHTML = "";
  for (const [tk, mkt] of pairs) {
    if (!tk || seen.has(tk)) continue;
    seen.add(tk);
    const b = document.createElement("button");
    b.className = "chip";
    b.textContent = tk;
    b.addEventListener("click", () => onTicker(tk, mkt));
    bar.appendChild(b);
  }
  bar.hidden = seen.size === 0;
}

async function onTicker(tk, mktHint, nm) {
  const mkt = tickerMarket(tk) || mktHint;
  if (nm) tickerNames[tk] = nm;
  const hit = await reportGet(mkt, tk);
  if (hit && hit.fresh) {
    const mins = Math.round(hit.age / 60000);
    await showResult(hit.payload, tk, null);
    currentTicker = tk;
    status(`📊 ${tk} · 本地缓存 ${mins < 1 ? "刚刚" : mins + " 分钟前"} · 点「按需」可重新分析 · v${APP_VERSION}`);
    return;
  }
  // 没有或已过期 —— 弹窗确认
  openModal({ ticker: tk, name: nm || tickerNames[tk] || "", note: hit
    ? `本地有一份 ${Math.round(hit.age / 60000)} 分钟前的报告（已过期），可重新分析` : "" });
}

/* 统一的弹窗入口。ticker 有值即预填并切到「个股分析」，标题也随之变化，
   这样一眼就能看出弹窗是点代码来的还是点「按需」来的。 */
function openModal({ ticker = "", name = "", note = "" } = {}) {
  const isTk = !!ticker;
  const nm = name || tickerNames[ticker] || "";
  document.querySelector(`input[name=job][value=${isTk ? "ticker" : "brief"}]`).checked = true;
  $("ticker").value = ticker;
  $("modaltitle").textContent = isTk ? (nm ? `分析 ${nm} ${ticker}` : `分析 ${ticker}`)
                                     : "按需运行";
  if (!isTk) $("reqmarket").value = $("market").value.startsWith("job:") ? "cn" : $("market").value;
  syncMarketLock();
  $("modal").hidden = false;
  refreshModal(note);
}

/* ---------- 自选清单管理 ---------- */
let mgmtTicker = null;

function openMgmt(tk, nm) {
  mgmtTicker = tk;
  const isUS = tickerMarket(tk) === "us";
  $("mgmttitle").textContent = `管理 ${nm || tickerNames[tk] || ""} ${tk}`.trim();
  $("mname").value = nm || tickerNames[tk] || "";
  $("mcost").value = ""; $("mqty").value = "";
  ["mkind", "mcost", "mqty", "mname", "msave"].forEach((id) => { $(id).disabled = false; });
  // 「期权」类型只对美股有意义（备兑看涨标的）
  const opt = [...$("mkind").options].find((o) => o.value === "options");
  opt.hidden = !isUS; opt.disabled = !isUS;
  if (!isUS && $("mkind").value === "options") $("mkind").value = "swing";
  $("mgmtnote").textContent = "留空的字段不会被改动；成本留空表示清除持仓记录。";
  $("mgmt").hidden = false;
}

async function sendMgmt(action, extra) {
  const tk = mgmtTicker;
  $("mgmt").hidden = true;
  const body = { job: "watchlist", action, ticker: tk,
                 market: tickerMarket(tk) || "cn",
                 ai: false, ts: Math.floor(Date.now() / 1000), ...extra };
  try {
    const r = await signedPost(body);
    const j = await r.json();
    if (!r.ok) { status("⚠ " + (j.error || r.status), true); return; }
    const rec = { ...body, id: j.id, label: `${tk} ${action}`, ts: Date.now() };
    await histAdd(rec);
    await rebuildMarketSelect("job:" + j.id);
    pollJob(j.id, rec, null);
  } catch (e) { status("⚠ " + e.message, true); }
}

$("tomgmt").addEventListener("click", () => {
  const tk = $("ticker").value.trim().toUpperCase();
  if (!tk) return;
  $("modal").hidden = true;
  openMgmt(tk, tickerNames[tk] || "");
});
$("mclose").addEventListener("click", () => { $("mgmt").hidden = true; });
$("mgmt").addEventListener("click", (e) => { if (e.target.id === "mgmt") $("mgmt").hidden = true; });
$("mremove").addEventListener("click", () => {
  if (confirm(`确定把 ${mgmtTicker} 从自选移除？持仓记录也会一并清除。`)) sendMgmt("remove");
});
$("msave").addEventListener("click", async () => {
  const tk = mgmtTicker;
  const nm = $("mname").value.trim();
  const cost = $("mcost").value.trim();
  const qty = $("mqty").value.trim();
  // 按需依次提交，每次一个动作，服务端串行执行
  if (nm && nm !== (tickerNames[tk] || "")) { await sendMgmt("rename", { name: nm }); return; }
  if (cost !== "") { await sendMgmt("position", { cost, qty: qty || null }); return; }
  await sendMgmt("kind", { kind: $("mkind").value });
});

/* ---------- 后台轮询：与「当前在看什么」解耦 ----------
 * 任务一旦提交就在后台轮询到底。切换下拉框、点刷新、退出重进都不会打断它，
 * 也不会重复起第二个轮询。进度常驻显示在「按需」按钮上。 */
let activeJob = null;
let currentTicker = null;      // 当前展示的是哪只票的报告；看简报时为 null
const tickerNames = {};        // 代码 -> 公司名，用于弹窗标题

function markBusy(job) {
  const b = $("ondemand");
  if (!job) { b.textContent = "按需"; b.classList.remove("busy"); return; }
  const sec = Math.round((Date.now() - job.t0) / 1000);
  b.textContent = `分析中 ${sec}s`;
  b.classList.add("busy");
}

function viewingJob(id) { return $("market").value === "job:" + id; }

async function pollJob(id, rec, left) {
  if (activeJob && activeJob.id === id) return;          // 已在轮询，不重复起
  const label = rec ? rec.label : id;
  const est = (rec && rec.ai) ? "约 60–90 秒" : "约 10 秒";
  activeJob = { id, label, t0: Date.now() };
  markBusy(activeJob);
  const tick = setInterval(() => markBusy(activeJob), 1000);

  try {
    while (Date.now() - activeJob.t0 < waitMs()) {
      if (viewingJob(id)) {
        const sec = Math.round((Date.now() - activeJob.t0) / 1000);
        status(`正在分析 ${label}…（${est}，已 ${sec}s）`
               + (left == null ? "" : ` · 今日剩 ${left}`));
      }
      await new Promise((r) => setTimeout(r, pollMs()));

      let res;
      try { res = await apiResult(id); }
      catch { continue; }
      if (res.status === 202) continue;
      if (!res.ok) {
        if (viewingJob(id)) status(`取回失败：HTTP ${res.status}`, true);
        return;
      }

      const p = await res.json();
      await histMark(id, true);
      await rebuildMarketSelect($("market").value);
      if (p.error) {
        if (viewingJob(id)) status(`${label} 执行失败：${p.error}（可重试）`, true);
        else status(`⚠ ${label} 执行失败，可从下拉框查看`, true);
        return;
      }
      if (rec && rec.job === "ticker" && rec.ticker)
        await reportPut(tickerMarket(rec.ticker) || rec.market, rec.ticker, p,
                        tickerNames[rec.ticker] || "");
      if (viewingJob(id)) {
        await showResult(p, label, left);
      } else {
        status(`✅ ${label} 分析完成 —— 从下拉框选「📊 ${label}」查看`);
      }
      return;
    }
    status(`${label} 仍在运行，稍后从下拉框取回（结果保留 48 小时）`, true);
  } finally {
    clearInterval(tick);
    activeJob = null;
    markBusy(null);
  }
}

async function showResult(p, label, left) {
  currentTicker = p && p.job === "ticker" ? (p.ticker || null) : null;
  // 看个股报告时，代码条只列同市场且本地研究过的标的
  if (currentTicker)
    setTimeout(() => buildChipsFrom("", tickerMarket(currentTicker)), 0);
  const priv = await sessionKey();
  if (!priv) { show("unlock"); status("已锁定，请重新解锁"); return; }
  try {
    $("frame").style.height = "60vh";
    delete $("frame").dataset.zoomed;
    $("frame").srcdoc = injectClicks(await decryptPayload(p, priv));
    show("content");
    const tag = p.cached ? `缓存 ${p.cache_age_min} 分钟前` : "刚生成";
    status(`📊 ${label} · ${tag}`
           + (left == null ? "" : ` · 今日剩 ${left}`) + ` · v${APP_VERSION}`);
  } catch (e) { status("解密失败：" + e.message, true); }
}

$("refresh").addEventListener("click", render);
$("market").addEventListener("change", render);
$("lock").addEventListener("click", async () => { await kvDel("session"); show("unlock"); status("已锁定"); });
$("reset").addEventListener("click", async () => {
  if (!confirm("删除本机私钥与缓存？需重新导入。")) return;
  await kvDel("wrapped"); await kvDel("session");
  await kvDel("cache-us"); await kvDel("cache-cn");
  await kvDel("history"); await kvDel("reports");
  show("setup"); status("已清除");
});

(async function init() {
  if (!crypto?.subtle) { status("需要 HTTPS 才能使用加密功能", true); return; }
  // iOS Safari 不支持 persist()，且可能在长期不用后清掉 IndexedDB —— 届时需重新导入私钥
  if (navigator.storage?.persist) { try { await navigator.storage.persist(); } catch {} }
  if ("serviceWorker" in navigator) {
    try {
      const reg = await navigator.serviceWorker.register("./sw.js");
      reg.update();                                  // 每次启动主动查更新
      let reloading = false;
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (reloading) return;
        reloading = true;
        location.reload();                           // 新版接管后刷新一次
      });
      if (reg.waiting) reg.waiting.postMessage("skipWaiting");
      reg.addEventListener("updatefound", () => {
        const w = reg.installing;
        w && w.addEventListener("statechange", () => {
          if (w.state === "installed" && navigator.serviceWorker.controller) {
            w.postMessage("skipWaiting");
          }
        });
      });
    } catch {}
  }
  const last = await kvGet("lastMarket");
  await rebuildMarketSelect(last);
  // 退出/锁屏期间可能有任务还在跑，回来继续轮询
  for (const x of await histGet()) if (!x.done) { pollJob(x.id, x, null); break; }
  if (!(await kvGet("wrapped"))) { show("setup"); return; }
  if (await sessionKey()) { await render(); } else { show("unlock"); }
})();
