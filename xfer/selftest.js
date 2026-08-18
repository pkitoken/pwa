/* 端到端自检：不联网，纯本机跑一遍封包/拆包/验签/花名册签名。 */

import * as C from './crypto.js';
import * as I from './invite.js';
import * as QR from './qr.js';

const out = document.getElementById('out');
let pass = 0, fail = 0;

function log(name, ok, detail) {
  const li = document.createElement('li');
  li.className = 'item';
  const n = document.createElement('div');
  n.className = 'n';
  n.textContent = (ok ? '✓ ' : '✗ ') + name;
  n.style.color = ok ? 'var(--good)' : 'var(--bad)';
  li.appendChild(n);
  if (detail) {
    const m = document.createElement('div');
    m.className = 'm';
    m.textContent = detail;
    li.appendChild(m);
  }
  out.appendChild(li);
  if (ok) pass++; else fail++;
}

async function t(name, fn) {
  try { const d = await fn(); log(name, true, d || ''); }
  catch (e) { log(name, false, e && e.message ? e.message : String(e)); }
}

function assert(c, m) { if (!c) throw new Error(m || '断言失败'); }

function same(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function person(name) {
  const dh = await C.genDh(), sg = await C.genSig();
  const dhPub = await C.exportPub(dh.publicKey);
  return {
    uid: name, name: name,
    dhPriv: dh.privateKey, sigPriv: sg.privateKey,
    dh: dhPub, sig: await C.exportPub(sg.publicKey),
    kid: await C.kidOf(dhPub),
    dhJwk: await C.exportJwk(dh.privateKey)
  };
}

(async function run() {
  await t('base64 / base64url 往返', () => {
    const b = crypto.getRandomValues(new Uint8Array(3001));
    assert(same(C.unb64(C.b64(b)), b), 'b64 往返不一致');
    assert(same(C.unb64u(C.b64u(b)), b), 'b64u 往返不一致');
    assert(C.b64u(b).indexOf('=') < 0, 'b64u 不该有填充');
    return b.length + ' 字节';
  });

  await t('大缓冲区分片编码（1.5 MB，验证不爆栈）', () => {
    const b = new Uint8Array(1500000);
    for (let i = 0; i < b.length; i += 7919) b[i] = i & 255;
    assert(same(C.unb64(C.b64(b)), b), '大块 b64 往返不一致');
    return '1.5 MB 通过';
  });

  await t('hex 往返与 u32 编码', () => {
    const b = crypto.getRandomValues(new Uint8Array(16));
    assert(same(C.unhex(C.hex(b)), b), 'hex 往返不一致');
    assert(C.readU32(C.u32(123456789), 0) === 123456789, 'u32 不一致');
    return '';
  });

  const alice = await person('alice');
  const bob = await person('bob');
  const eve = await person('eve');

  await t('私钥 JWK 能推出同一个公钥（导入身份时要用）', () => {
    assert(C.pubFromJwk(alice.dhJwk) === alice.dh, '推出来的公钥对不上');
    return alice.kid;
  });

  const data = crypto.getRandomValues(new Uint8Array(65536));
  let sealed = null;

  await t('封包给两个收件人', async () => {
    sealed = await C.seal(data, { name: '报表.pdf', type: 'application/pdf', ts: Date.now() },
      [{ kid: alice.kid, dh: alice.dh }, { kid: bob.kid, dh: bob.dh }],
      { uid: 'carol', name: '卡罗', sigPriv: (await person('carol')).sigPriv, sigPub: '' });
    assert(sealed.recips.length === 2, '封装包数量不对');
    assert(sealed.blob.length > data.length, '密文比明文还短？');
    return '密文 ' + sealed.blob.length + ' 字节，封装包 2 份';
  });

  /* 上面那个 carol 是临时的，正式流程要用同一把签名钥匙，这里重来一次 */
  const carol = await person('卡罗');
  await t('封包（正式，带可验证的发件人）', async () => {
    sealed = await C.seal(data, { name: '报表.pdf', type: 'application/pdf', ts: Date.now() },
      [{ kid: alice.kid, dh: alice.dh }, { kid: bob.kid, dh: bob.dh }],
      { uid: carol.uid, name: carol.name, sigPriv: carol.sigPriv, sigPub: carol.sig });
    return sealed.id;
  });

  const entry = { id: sealed.id, epk: sealed.epk, recips: sealed.recips, ts: Date.now(), p: 'ack', acks: [] };

  await t('收件人 A 先看摘要（不下载正文）', async () => {
    const pv = await C.peek(entry, alice.dhPriv, alice.kid);
    assert(pv && pv.n === '报表.pdf', '摘要解不出文件名');
    assert(pv.f === '卡罗', '摘要里发件人不对');
    return pv.n + ' / ' + pv.f;
  });

  await t('收件人 A 解密并验签', async () => {
    const r = await C.open(entry, sealed.blob, alice.dhPriv, alice.kid);
    assert(same(r.data, data), '解出来的内容和原文不一致');
    assert(r.meta.n === '报表.pdf', '文件名不对');
    assert(r.trusted === true, '验签没通过');
    assert(r.meta.from.sig === carol.sig, '签名公钥对不上发件人');
    return r.meta.s + ' 字节还原一致';
  });

  await t('收件人 B 也能独立解开', async () => {
    const r = await C.open(entry, sealed.blob, bob.dhPriv, bob.kid);
    assert(same(r.data, data), '内容不一致');
    assert(r.trusted === true, '验签没通过');
    return 'ok';
  });

  await t('局外人拿到密文和索引也解不开', async () => {
    try {
      await C.open(entry, sealed.blob, eve.dhPriv, eve.kid);
      throw new Error('居然解开了');
    } catch (e) {
      assert(e.message.indexOf('不是发给你的') >= 0, '拒绝的理由不对：' + e.message);
      return '按预期被拒';
    }
  });

  await t('冒用别人的封装包也解不开', async () => {
    const forged = { id: entry.id, epk: entry.epk, ts: entry.ts,
      recips: [{ kid: eve.kid, w: entry.recips[0].w, pv: entry.recips[0].pv }] };
    try {
      await C.open(forged, sealed.blob, eve.dhPriv, eve.kid);
      throw new Error('居然解开了');
    } catch (e) {
      assert(e.message.indexOf('解不开') >= 0 || e.message.indexOf('校验失败') >= 0, '理由不对：' + e.message);
      return '按预期被拒';
    }
  });

  await t('密文被改一个字节就报错', async () => {
    const bad = sealed.blob.slice();
    bad[bad.length - 40] ^= 1;
    try {
      await C.open(entry, bad, alice.dhPriv, alice.kid);
      throw new Error('改了还能解开');
    } catch (e) {
      assert(e.message.indexOf('校验失败') >= 0, '理由不对：' + e.message);
      return 'GCM 认证生效';
    }
  });

  await t('转封给第三人后验签必然失败', async () => {
    /* 拿原样密文换一批收件人 —— 签名覆盖了 kid 列表，所以对不上 */
    const s2 = await C.seal(data, { name: 'x', type: '', ts: Date.now() },
      [{ kid: eve.kid, dh: eve.dh }], { uid: carol.uid, name: carol.name, sigPriv: carol.sigPriv, sigPub: carol.sig });
    const mixed = { id: s2.id, epk: s2.epk, ts: Date.now(),
      recips: [{ kid: eve.kid, w: s2.recips[0].w, pv: s2.recips[0].pv },
               { kid: alice.kid, w: s2.recips[0].w, pv: s2.recips[0].pv }] };
    const r = await C.open(mixed, s2.blob, eve.dhPriv, eve.kid);
    assert(r.trusted === false, '收件人列表被改了，验签却还通过');
    return '签名把收件人列表也锁住了';
  });

  await t('花名册签名与篡改检测', async () => {
    const kp = await C.genSig();
    const pub = await C.exportPub(kp.publicKey);
    const body = JSON.stringify({ v: 1, ts: 1, people: [{ uid: 'a', name: '甲', groups: ['家人'], dh: alice.dh, sig: alice.sig }] });
    const sig = await C.signRoster(body, kp.privateKey);
    assert(await C.verifyRoster(body, sig, pub) === true, '正常花名册验不过');
    const tampered = body.replace(alice.dh, eve.dh);
    assert(await C.verifyRoster(tampered, sig, pub) === false, '换掉公钥居然还验得过');
    const other = await C.genSig();
    assert(await C.verifyRoster(body, sig, await C.exportPub(other.publicKey)) === false, '别人的公钥也验得过');
    return '三种情况都符合预期';
  });

  await t('邀请码编解码往返', () => {
    const inv = { v: 1, uid: 'zhangsan', name: '张三', dh: alice.dhJwk, sig: alice.dhJwk,
      repo: { owner: 'o', name: 'r', branch: 'main', token: 't' } };
    const code = 'TXFID1.' + C.b64u(C.utf8(JSON.stringify(inv)));
    const back = JSON.parse(C.fromUtf8(C.unb64u(code.slice(7))));
    assert(back.uid === 'zhangsan' && back.name === '张三', '中文姓名没还原');
    assert(back.repo.token === 't', '仓库信息丢了');
    return code.length + ' 字符';
  });

  await t('邀请码打包/解包往返（含中文、令牌、过期）', async () => {
    const dh = await C.genDh(), sg = await C.genSig();
    const inv = {
      kind: I.KIND_ADMIN, nonce: C.randHex(8), exp: 1893456000,
      dh: await C.exportJwk(dh.privateKey), sig: await C.exportJwk(sg.privateKey),
      uid: 'zhangsan', name: '张三',
      repo: { owner: 'pkitoken', repo: 'xfer-private', branch: 'main',
              token: 'github_pat_' + new Array(83).join('x') }
    };
    const bytes = I.packInvite(inv);
    const back = I.inviteFromText(I.inviteToText(bytes));
    assert(back.uid === 'zhangsan' && back.name === '张三', '姓名没还原');
    assert(back.nonce === inv.nonce, 'nonce 没还原');
    assert(back.exp === inv.exp, '过期时间没还原');
    assert(back.repo.token === inv.repo.token, '令牌没还原');
    assert(back.repo.repo === 'xfer-private', '仓库名没还原');
    /* 拆出来的私钥必须还能推回同一把公钥，否则 kid 就对不上了 */
    assert(C.pubFromJwk(back.dh) === await C.exportPub(dh.publicKey), 'ECDH 公钥对不上');
    assert(C.pubFromJwk(back.sig) === await C.exportPub(sg.publicKey), 'ECDSA 公钥对不上');
    /* 链接形态也要认 */
    const viaUrl = I.inviteFromText(I.inviteToUrl('https://x.test/pwa/xfer/', bytes));
    assert(viaUrl.nonce === inv.nonce, 'URL 形态解不出来');
    return bytes.length + ' 字节 → ' + I.inviteToText(bytes).length + ' 字符';
  });

  await t('从邀请码还原出来的钥匙能真的收发', async () => {
    const dh = await C.genDh(), sg = await C.genSig();
    const bytes = I.packInvite({
      kind: 0, nonce: C.randHex(8), exp: 1893456000,
      dh: await C.exportJwk(dh.privateKey), sig: await C.exportJwk(sg.privateKey),
      uid: 'bob', name: '鲍勃', repo: { owner: 'o', repo: 'r', branch: 'main', token: 't' }
    });
    const back = I.inviteFromText(I.inviteToText(bytes));
    const priv = await C.importDhPriv(back.dh);          /* 手搭的 JWK 能不能进 WebCrypto */
    const pub = C.pubFromJwk(back.dh);
    const kid = await C.kidOf(pub);
    const payload = crypto.getRandomValues(new Uint8Array(2048));
    const sealed = await C.seal(payload, { name: '测试.bin', type: '', ts: Date.now() },
      [{ kid: kid, dh: pub }],
      { uid: 'alice', name: '爱丽丝', sigPriv: (await C.genSig()).privateKey, sigPub: '' });
    const entry = { id: sealed.id, epk: sealed.epk, recips: sealed.recips };
    const r = await C.open(entry, sealed.blob, priv, kid);
    assert(same(r.data, payload), '解出来的内容不一致');
    return '2 KB 往返一致';
  });

  await t('二维码：与参考实现逐模块一致（三组固定向量）', async () => {
    /* 期望值来自本机 Python 实现，那份已和 Nayuki 的参考实现（MIT）在 77 组
       用例上逐模块对齐过。这里只验 JS 移植有没有抄错。 */
    const V = [
      { d: C.utf8('A'), ecl: 0, ver: 1, size: 21, mask: 0,
        sha: '4597c26c5a34a79c80006146bbb14ade03f6a4c8ae35407ee421e7e2830adefc' },
      { d: C.utf8('https://pkitoken.github.io/pwa/xfer/#i=' + new Array(445).join('A')),
        ecl: 1, ver: 17, size: 85, mask: 0,
        sha: '9fb8b6f3dbca561c8873af7c809ace922e4dc8bca0feb1e65753ef95b3361cc8' },
      { d: C.utf8('文件互传 邀请码 测试'), ecl: 2, ver: 3, size: 29, mask: 0,
        sha: '9735f3010e4141e4aebb23327a4fb7cc6c200f82bd47201b34f8e50ef87dffbe' }
    ];
    for (const v of V) {
      const q = QR.encodeQr(v.d, v.ecl);
      assert(q.ver === v.ver, '版本应为 ' + v.ver + '，实际 ' + q.ver);
      assert(q.size === v.size, '尺寸应为 ' + v.size + '，实际 ' + q.size);
      assert(q.mask === v.mask, '掩码应为 ' + v.mask + '，实际 ' + q.mask);
      const flat = new Uint8Array(q.size * q.size);
      for (let y = 0; y < q.size; y++)
        for (let x = 0; x < q.size; x++) flat[y * q.size + x] = q.mod[y][x];
      const h = C.hex(new Uint8Array(await crypto.subtle.digest('SHA-256', flat)));
      assert(h === v.sha, '模块指纹不符：' + h.slice(0, 16) + '…');
    }
    return '3 组全中（版本 1 / 17 / 3）';
  });

  await t('二维码：SVG 画得出来，尺寸合理', () => {
    const q = QR.qrSvg(C.utf8('https://pkitoken.github.io/pwa/xfer/#i=' + new Array(445).join('A')), { ecl: 1 });
    assert(q.svg.indexOf('<svg') === 0, '不是 SVG');
    assert(q.svg.indexOf('viewBox="0 0 93 93"') > 0, '静默区不对（应为 85+4+4=93）');
    assert(q.svg.length > 1000, 'SVG 内容太短，八成没画出来');
    /* 尺寸必须是模块数的整数倍，且落在能扫的范围里——否则会像 1.0 那样
       被 CSS 拉成三四十厘米，手机反而扫不动 */
    assert(q.px === 93 * q.scale, '像素尺寸不是模块的整数倍');
    assert(q.scale >= 3, '每模块只有 ' + q.scale + 'px，屏幕上太细了');
    assert(q.px >= 240 && q.px <= 560, '整体 ' + q.px + 'px，不在好扫的范围');
    assert(q.svg.indexOf('width="' + q.px + '"') > 0, 'SVG 没写死宽度');
    return '版本 ' + q.ver + '，' + q.px + 'px（每模块 ' + q.scale + 'px）';
  });

  /* 最后放一张真码出来，让人拿相机扫一下——这是唯一能验证「真解码器读得懂」
     的办法，逐模块比对只能证明和参考实现一致。 */
  const probe = 'TXF2-selftest-' + new Date().toISOString().slice(0, 10);
  document.getElementById('scanExpect').textContent = probe;
  const sq = QR.qrSvg(C.utf8(probe), { ecl: 1 });
  document.getElementById('scanQr').innerHTML = sq.svg;
  document.getElementById('scanMeta').textContent =
    '版本 ' + sq.ver + ' · ' + sq.size + '×' + sq.size + ' 模块 · ' + sq.px + 'px（每模块 ' +
    sq.scale + 'px）· 手机离屏幕 20–30 厘米，整张连白边一起框进去';

  const s = document.getElementById('sum');
  s.textContent = pass + ' 通过 / ' + fail + ' 失败';
  s.style.color = fail ? 'var(--bad)' : 'var(--good)';
})();
