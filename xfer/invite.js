/* =========================================================================
   邀请码编解码 —— 紧凑二进制格式 TXF2。

   为什么不用 JSON：两把 P-256 私钥写成 JWK，光是 "crv":"P-256","kty":"EC"
   这类样板就重复两遍，整串 845 个字符，二维码要排到版本 30 以上，手机屏幕
   上密到扫不动。私钥其实只是六个 32 字节的大数，直接按字节摆，347 字节、
   464 个字符，做成链接二维码是版本 17，正常距离一扫就中。

   布局（全部大端）：
     0..3     magic "TXF2"
     4        格式版本 = 1
     5        标志位：bit0 = 1 表示这是设备配对码，0 表示管理员签发
     6..13    nonce（8 字节）—— 一次性凭据的编号，领取后作废
     14..17   过期时刻（uint32 秒）
     18..113  ECDH  d ‖ x ‖ y
     114..209 ECDSA d ‖ x ‖ y
     210..    六个「1 字节长度 + UTF-8」的字符串：
              uid, name, owner, repo, branch, token
   ========================================================================= */

import { b64u, unb64u, concat, utf8, fromUtf8, hex, unhex } from './crypto.js';

const MAGIC = 'TXF2';
const HDR = 18;
const KEYS = 192;

export const KIND_ADMIN = 0;
export const KIND_PAIR = 1;

/* JWK 里的 d/x/y 本来就是 base64url 的 32 字节大数，来回换成原始字节即可 */
function rawOf(jwk) {
  return concat(unb64u(jwk.d), unb64u(jwk.x), unb64u(jwk.y));
}

function jwkOf(raw, off, ops) {
  return {
    kty: 'EC', crv: 'P-256', ext: true, key_ops: ops,
    d: b64u(raw.subarray(off, off + 32)),
    x: b64u(raw.subarray(off + 32, off + 64)),
    y: b64u(raw.subarray(off + 64, off + 96))
  };
}

function packStrings(list) {
  const parts = [];
  for (const s of list) {
    const b = utf8(s || '');
    if (b.length > 255) throw new Error('字段太长：' + s);
    parts.push(new Uint8Array([b.length]), b);
  }
  return concat.apply(null, parts);
}

/*  o = { kind, nonce(hex16), exp(秒), dh, sig, uid, name, repo{owner,repo,branch,token} } */
export function packInvite(o) {
  const head = new Uint8Array(HDR);
  head.set(utf8(MAGIC), 0);
  head[4] = 1;
  head[5] = o.kind || 0;
  head.set(unhex(o.nonce), 6);
  const e = o.exp >>> 0;
  head[14] = (e >>> 24) & 255; head[15] = (e >>> 16) & 255;
  head[16] = (e >>> 8) & 255;  head[17] = e & 255;

  return concat(head, rawOf(o.dh), rawOf(o.sig),
    packStrings([o.uid, o.name, o.repo.owner, o.repo.repo, o.repo.branch || 'main', o.repo.token || '']));
}

export function unpackInvite(bytes) {
  const b = new Uint8Array(bytes);
  if (b.length < HDR + KEYS + 6) throw new Error('邀请码不完整');
  if (fromUtf8(b.subarray(0, 4)) !== MAGIC) throw new Error('这不是一张邀请码');
  if (b[4] !== 1) throw new Error('邀请码版本不认识，先把应用更新到最新版');

  const keys = b.subarray(HDR, HDR + KEYS);
  const strs = [];
  let p = HDR + KEYS;
  for (let i = 0; i < 6; i++) {
    const n = b[p];
    strs.push(fromUtf8(b.subarray(p + 1, p + 1 + n)));
    p += 1 + n;
  }
  return {
    kind: b[5] & 1,
    nonce: hex(b.subarray(6, 14)),
    exp: ((b[14] << 24) | (b[15] << 16) | (b[16] << 8) | b[17]) >>> 0,
    dh: jwkOf(keys, 0, ['deriveBits']),
    sig: jwkOf(keys, 96, ['sign']),
    uid: strs[0], name: strs[1],
    repo: { owner: strs[2], repo: strs[3], branch: strs[4] || 'main', token: strs[5] }
  };
}

/* 文本形态：TXF2.<base64url>，用于复制粘贴（笔记本没摄像头时走这条） */
export const inviteToText = (bytes) => 'TXF2.' + b64u(bytes);

/* 链接形态：放在 # 后面，不会随请求发给服务器，GitHub Pages 那边看不到 */
export const inviteToUrl = (base, bytes) => base + '#i=' + b64u(bytes);

/* 三种写法都吃：完整链接、TXF2.xxx、或者光秃秃的一串 base64url */
export function inviteFromText(text) {
  let s = (text || '').trim().replace(/\s+/g, '');
  if (!s) throw new Error('内容是空的');
  const hash = s.indexOf('#i=');
  if (hash >= 0) s = s.slice(hash + 3);
  else if (s.indexOf('TXF2.') === 0) s = s.slice(5);
  return unpackInvite(unb64u(s));
}

/* =========================================================================
   口令加密的邀请件（TXF3）

   为什么要这一层：邀请码本体 347 字节，压不进一句能在电话里念的话。所以
   把两个渠道拆开——**密文走微信/短信/邮件都行，单独拿到毫无用处；口令你
   打电话念**。两样凑齐才解得开。

   布局：
     0..3    magic "TXF3"
     4       格式版本 = 1
     5..8    PBKDF2 迭代次数（uint32，写进去是为了以后能调高）
     9..24   盐（16 字节）
     25..36  IV（12 字节）
     37..    AES-256-GCM 密文，明文就是上面的 TXF2 邀请码

   ⚠️ 口令强度就是这层的全部安全性。密文一旦被截获，对方可以离线慢慢试，
   一次性 nonce 挡不住这件事——烧掉 nonce 只是让他不能再去领取，密文里的
   私钥和令牌照样会被解出来。所以口令别用成语、生日、诗句这类猜得到的东西。
   ========================================================================= */

const SEALED_MAGIC = 'TXF3';
export const KDF_ITERS = 600000;      /* 手机上约 1–2 秒，一次性操作，值得 */
export const MIN_HAN = 5;             /* 至少 5 个汉字 */

/* 去掉所有空白（含全角空格），再做 NFC 规范化——不同输入法打出来的同一句
   话在码位上可能不同，不规范化会出现「明明一样却解不开」。 */
export function normalizePass(s) {
  const t = (s || '').replace(/[\s　​-‍﻿]+/g, '');
  return t.normalize ? t.normalize('NFC') : t;
}

const HAN_RE = /[㐀-䶿一-鿿豈-﫿]/g;

export function checkPass(s) {
  const t = normalizePass(s);
  const han = (t.match(HAN_RE) || []).length;
  if (!t) return { ok: false, han: 0, why: '口令是空的' };
  if (han < MIN_HAN) return { ok: false, han: han, why: '至少要 ' + MIN_HAN + ' 个汉字，现在只有 ' + han + ' 个' };
  return { ok: true, han: han, why: '' };
}

async function passKey(pass, salt, iters) {
  const base = await crypto.subtle.importKey('raw', utf8(normalizePass(pass)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iters },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function sealInvite(inviteBytes, pass, iters) {
  const c = checkPass(pass);
  if (!c.ok) throw new Error(c.why);
  const n = iters || KDF_ITERS;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await passKey(pass, salt, n);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, inviteBytes));

  const head = new Uint8Array(9);
  head.set(utf8(SEALED_MAGIC), 0);
  head[4] = 1;
  head[5] = (n >>> 24) & 255; head[6] = (n >>> 16) & 255;
  head[7] = (n >>> 8) & 255;  head[8] = n & 255;
  return concat(head, salt, iv, ct);
}

export async function openSealed(bytes, pass) {
  const b = new Uint8Array(bytes);
  if (b.length < 38 || fromUtf8(b.subarray(0, 4)) !== SEALED_MAGIC) throw new Error('这不是一份口令邀请件');
  if (b[4] !== 1) throw new Error('邀请件版本不认识，先更新应用');
  const iters = ((b[5] << 24) | (b[6] << 16) | (b[7] << 8) | b[8]) >>> 0;
  if (iters < 10000 || iters > 5000000) throw new Error('迭代次数不合常理，文件可能坏了');

  const key = await passKey(pass, b.subarray(9, 25), iters);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(25, 37) }, key, b.subarray(37));
  } catch { throw new Error('口令不对'); }
  return unpackInvite(new Uint8Array(plain));
}

export const sealedToText = (bytes) => SEALED_MAGIC + '.' + b64u(bytes);

/* 加密件也做成链接，好处是可以直接印成二维码：拍张照发出去，口令电话里念。
   用 #s= 区别于明文的 #i=，应用一看前缀就知道要不要问口令。 */
export const sealedToUrl = (base, bytes) => base + '#s=' + b64u(bytes);

export function isSealedText(text) {
  const s = (text || '').trim().replace(/\s+/g, '');
  return s.indexOf(SEALED_MAGIC + '.') === 0;
}

export function sealedFromText(text) {
  const s = (text || '').trim().replace(/\s+/g, '');
  if (!isSealedText(s)) throw new Error('这不是一份口令邀请件');
  return unb64u(s.slice(SEALED_MAGIC.length + 1));
}
