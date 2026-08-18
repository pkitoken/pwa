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
