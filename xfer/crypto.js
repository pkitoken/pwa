/* =========================================================================
   密码学核心 —— 全部使用浏览器原生 WebCrypto，无第三方库、无构建步骤。

   设计要点
   ---------------------------------------------------------------------
   · 每个人两把 P-256 密钥：dh 用于 ECDH 封装会话密钥，sig 用于 ECDSA 签名。
     一把钥匙不同时用于两种算法，避免跨协议风险，代价只是多几百字节。
   · 每个文件一把随机 AES-256-GCM 会话密钥（CEK），文件本体只加密一次；
     CEK 再用「临时 ECDH 公钥 × 每个收件人公钥」分别封装一份。
     所以 10 个收件人只多 10 个 100 字节的小包，不是 10 份密文。
   · 索引里只出现 kid（公钥哈希前 8 字节）和封装包，文件名、发件人、
     大小全部在密文信封内，拿到仓库也看不出谁给谁发了什么。
   · 签名覆盖 blobId + 收件人 kid 列表 + 文件哈希，因此别人无法把一份
     签好名的密文转封给第三方冒充原发件人（surreptitious forwarding）。
   ========================================================================= */

const te = new TextEncoder();
const td = new TextDecoder();

export const MAGIC = 'TXF1';
const EC = { name: 'ECDH', namedCurve: 'P-256' };
const ES = { name: 'ECDSA', namedCurve: 'P-256' };

/* ---------------------------------------------------------------- 字节工具 */

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function u32(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

export function readU32(b, off) {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

export function hex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function unhex(s) {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function randHex(n) { return hex(crypto.getRandomValues(new Uint8Array(n))); }

/* btoa/atob 只吃 latin1 字符串。整块 String.fromCharCode 在 20 MB 上会爆栈，
   所以按 32 KB 分片——这是唯一能同时兼顾老 WebKit 和大文件的写法。 */
const CH = 0x8000;

export function b64(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += CH) s += String.fromCharCode.apply(null, b.subarray(i, i + CH));
  return btoa(s);
}

export function unb64(str) {
  const bin = atob(str.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64u(buf) {
  return b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  return unb64(s + '==='.slice((s.length + 3) % 4));
}

export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);

/* ---------------------------------------------------------------- 密钥管理 */

export function genDh() {
  return crypto.subtle.generateKey(EC, true, ['deriveBits']);
}

export function genSig() {
  return crypto.subtle.generateKey(ES, true, ['sign', 'verify']);
}

export async function exportPub(key) {
  return b64u(await crypto.subtle.exportKey('raw', key));
}

export function exportJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}

/* EC 私钥 JWK 里本来就带着公钥坐标，拼成未压缩点即可，不必再进一次
   WebCrypto。0x04 是「未压缩」的前缀。 */
export function pubFromJwk(jwk) {
  return b64u(concat(new Uint8Array([4]), unb64u(jwk.x), unb64u(jwk.y)));
}

export const importDhPub  = (s) => crypto.subtle.importKey('raw', unb64u(s), EC, false, []);
export const importSigPub = (s) => crypto.subtle.importKey('raw', unb64u(s), ES, false, ['verify']);
export const importDhPriv  = (j) => crypto.subtle.importKey('jwk', j, EC, false, ['deriveBits']);
export const importSigPriv = (j) => crypto.subtle.importKey('jwk', j, ES, false, ['sign']);

/* kid = 公钥 SHA-256 的前 8 字节。索引里用它指代收件人：够短、不可逆，
   而且不必信任任何人自报的 uid。 */
export async function kidOf(dhPubB64u) {
  const h = await crypto.subtle.digest('SHA-256', unb64u(dhPubB64u));
  return hex(new Uint8Array(h).subarray(0, 8));
}

/* ---------------------------------------------------------- 会话密钥封装 */

/* HKDF 把 ECDH 出来的原始 32 字节拉伸成 AES 密钥。salt 用 blobId，info 里
   带上 kid——同一份密文发给两个人时两把 KEK 必然不同。 */
async function kekFor(privDh, pubDh, blobId, kid) {
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubDh }, privDh, 256);
  const base = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: unhex(blobId), info: utf8('xfer/kek/v1/' + kid) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/* 签名覆盖的内容：magic ‖ blobId ‖ 排序后的收件人 kid ‖ 文件明文哈希 */
async function sigPayload(blobId, kids, fileHash) {
  return concat(utf8(MAGIC + blobId + kids.slice().sort().join(',')), fileHash);
}

/* -------------------------------------------------------------------- 封包 */

/*  recips: [{ kid, dh }]（dh 为 base64url 原始公钥）
    me:     { uid, name, sigPriv, sigPub }
    返回:   { id, epk, recips:[{kid,w}], blob }                              */
export async function seal(fileBytes, fileMeta, recips, me) {
  const id = randHex(16);
  const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

  const fileHash = new Uint8Array(await crypto.subtle.digest('SHA-256', fileBytes));
  const kids = recips.map((r) => r.kid);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, me.sigPriv,
    await sigPayload(id, kids, fileHash));

  const meta = {
    n: fileMeta.name, t: fileMeta.type || 'application/octet-stream',
    s: fileBytes.length, ts: fileMeta.ts,
    from: { uid: me.uid, name: me.name, sig: me.sigPub },
    h: b64u(fileHash), sg: b64u(sig)
  };
  const metaBytes = utf8(JSON.stringify(meta));

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek,
    concat(u32(metaBytes.length), metaBytes, fileBytes)));
  const blob = concat(utf8(MAGIC), iv, ct);

  /* 除了封装 CEK，再给每个收件人塞一小段加密摘要（文件名、发件人、大小）。
     这样收件箱不用先下载几十兆密文就能显示「谁发来的什么文件」，而摘要
     和正文用的是同一把 KEK，别人照样看不到。 */
  const preview = utf8(JSON.stringify({ n: meta.n, s: meta.s, f: me.name || me.uid }));

  const eph = await genDh();
  const rawCek = new Uint8Array(await crypto.subtle.exportKey('raw', cek));
  const wrapped = [];
  for (const r of recips) {
    const k = await kekFor(eph.privateKey, await importDhPub(r.dh), id, r.kid);
    const wiv = crypto.getRandomValues(new Uint8Array(12));
    const w = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wiv }, k, rawCek));
    const piv = crypto.getRandomValues(new Uint8Array(12));
    const pv = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: piv }, k, preview));
    wrapped.push({ kid: r.kid, w: b64u(concat(wiv, w)), pv: b64u(concat(piv, pv)) });
  }

  return { id, epk: await exportPub(eph.publicKey), recips: wrapped, blob };
}

/* -------------------------------------------------------------------- 拆包 */

async function myKek(entry, myDhPriv, myKid) {
  return kekFor(myDhPriv, await importDhPub(entry.epk), entry.id, myKid);
}

/* 只解那一小段摘要，不碰密文本体。收件箱刷新时对每条自己的条目跑一次。 */
export async function peek(entry, myDhPriv, myKid) {
  const slot = entry.recips.find((r) => r.kid === myKid);
  if (!slot || !slot.pv) return null;
  try {
    const kek = await myKek(entry, myDhPriv, myKid);
    const p = unb64u(slot.pv);
    const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.subarray(0, 12) }, kek, p.subarray(12));
    return JSON.parse(fromUtf8(new Uint8Array(out)));
  } catch { return null; }
}

/*  entry: 索引条目；myDhPriv: 自己的 ECDH 私钥；myKid: 自己的 kid
    返回:  { meta, data, trusted }                                           */
export async function open(entry, blobBytes, myDhPriv, myKid) {
  const slot = entry.recips.find((r) => r.kid === myKid);
  if (!slot) throw new Error('这份文件不是发给你的');

  const kek = await myKek(entry, myDhPriv, myKid);
  const packed = unb64u(slot.w);
  let rawCek;
  try {
    rawCek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: packed.subarray(0, 12) }, kek, packed.subarray(12));
  } catch { throw new Error('会话密钥解不开——身份不对，或索引被改过'); }
  const cek = await crypto.subtle.importKey('raw', rawCek, { name: 'AES-GCM' }, false, ['decrypt']);

  const b = new Uint8Array(blobBytes);
  if (fromUtf8(b.subarray(0, 4)) !== MAGIC) throw new Error('文件格式不对');
  let env;
  try {
    env = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b.subarray(4, 16) }, cek, b.subarray(16)));
  } catch { throw new Error('密文校验失败——文件在仓库里被改动过'); }

  const mlen = readU32(env, 0);
  const meta = JSON.parse(fromUtf8(env.subarray(4, 4 + mlen)));
  const data = env.subarray(4 + mlen);

  /* 验签：确认确实是 meta.from 声称的那把签名钥匙签的，且签的正是这份
     文件、这个 blobId、这批收件人。调用方还要再拿 meta.from.sig 去花名册
     里核对一次，才能把「某把钥匙」对上「某个人」。 */
  let trusted = false;
  try {
    const fh = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    trusted = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' },
      await importSigPub(meta.from.sig), unb64u(meta.sg),
      await sigPayload(entry.id, entry.recips.map((r) => r.kid), fh));
  } catch { trusted = false; }

  return { meta, data, trusted };
}

/* ------------------------------------------------------------ 花名册签名 */

/* 花名册存成 { body: "<JSON 字符串>", sig }，签的就是那个字符串本身。
   不重新序列化，就不会因为键顺序或空格差异导致验签莫名其妙失败。 */
export async function signRoster(bodyStr, adminSigPriv) {
  return b64u(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, adminSigPriv, utf8(bodyStr)));
}

export async function verifyRoster(bodyStr, sigB64u, adminPubB64u) {
  try {
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' },
      await importSigPub(adminPubB64u), unb64u(sigB64u), utf8(bodyStr));
  } catch { return false; }
}
