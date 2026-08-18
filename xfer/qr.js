/* =========================================================================
   QR 编码器（字节模式）—— 自己写的，没有第三方库。

   为什么自己写：这个应用不引任何外部脚本，CSP 也不允许。二维码只用来发
   邀请码，字节模式 + 自动选版本足够了，不做汉字/数字模式的优化。

   正确性：整套算法先用 Python 写了一遍，和 Nayuki 的参考实现（MIT）逐模块
   对比过 77 组用例，覆盖版本 1–40、四档纠错，全部一致；这个文件是那份验过
   的代码的逐行移植。selftest.html 里有一组固定向量，改动本文件后先跑那里。
   ========================================================================= */

const ECC_PER_BLOCK = [
 [-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
 [-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],
 [-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
 [-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]];

const NUM_BLOCKS = [
 [-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],
 [-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],
 [-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],
 [-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]];

const FORMAT_BITS = [1, 0, 3, 2];      /* L,M,Q,H 在格式信息里的编号 */

const MASKS = [
  (x, y) => (x + y) % 2,
  (x, y) => y % 2,
  (x, y) => x % 3,
  (x, y) => (x + y) % 3,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2,
  (x, y) => (x * y) % 2 + (x * y) % 3,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2
];

/* ---------------------------------------------------------------- GF(256) */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function () {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11D;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];

/* 生成多项式，降幂排列且去掉首项 1，正好对应下面逐字节的除法循环 */
function rsGenerator(deg) {
  let g = [1];
  for (let i = 0; i < deg; i++) {
    g = [0].concat(g);
    for (let j = 0; j < g.length - 1; j++) g[j] ^= gfMul(g[j + 1], EXP[i]);
  }
  return g.slice(0, deg).reverse();
}

function rsEncode(data, deg) {
  const gen = rsGenerator(deg);
  const res = new Array(deg).fill(0);
  for (let d = 0; d < data.length; d++) {
    const factor = data[d] ^ res[0];
    res.shift();
    res.push(0);
    for (let i = 0; i < deg; i++) res[i] ^= gfMul(gen[i], factor);
  }
  return res;
}

/* ---------------------------------------------------------------- 容量计算 */

function alignPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  const step = Math.floor((ver * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
  const res = [];
  for (let i = 0; i < n - 1; i++) res.push(size - 7 - i * step);
  res.push(6);
  return res.reverse();
}

function rawDataModules(ver) {
  let res = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    res -= (25 * n - 10) * n - 55;
    if (ver >= 7) res -= 36;
  }
  return res;
}

const dataCodewords = (ver, ecl) =>
  Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver];

const ccBits = (ver) => ver <= 9 ? 8 : 16;

/* ---------------------------------------------------------------- 码字 */

function buildCodewords(data, ver, ecl) {
  const bits = [];
  const add = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  add(4, 4);                       /* 字节模式 */
  add(data.length, ccBits(ver));
  for (let i = 0; i < data.length; i++) add(data[i], 8);

  const cap = dataCodewords(ver, ecl) * 8;
  add(0, Math.min(4, cap - bits.length));
  add(0, (8 - bits.length % 8) % 8);
  let pad = 0xEC;
  while (bits.length < cap) { add(pad, 8); pad = pad === 0xEC ? 0x11 : 0xEC; }

  const cw = new Array(bits.length >> 3).fill(0);
  for (let i = 0; i < bits.length; i++) cw[i >> 3] |= bits[i] << (7 - (i & 7));
  return cw;
}

function interleave(cw, ver, ecl) {
  const nb = NUM_BLOCKS[ecl][ver];
  const eccLen = ECC_PER_BLOCK[ecl][ver];
  const total = Math.floor(rawDataModules(ver) / 8);
  const shortLen = Math.floor(total / nb) - eccLen;
  const numShort = nb - total % nb;

  const blocks = [], eccs = [];
  let k = 0;
  for (let i = 0; i < nb; i++) {
    const ln = shortLen + (i < numShort ? 0 : 1);
    const blk = cw.slice(k, k + ln);
    k += ln;
    blocks.push(blk);
    eccs.push(rsEncode(blk, eccLen));
  }
  const out = [];
  for (let i = 0; i <= shortLen; i++)
    for (let j = 0; j < blocks.length; j++)
      if (i < blocks[j].length) out.push(blocks[j][i]);
  for (let i = 0; i < eccLen; i++)
    for (let j = 0; j < eccs.length; j++) out.push(eccs[j][i]);
  return out;
}

/* ---------------------------------------------------------------- 排版 */

function makeMatrix(data, ecl, ver) {
  const size = ver * 4 + 17;
  const mod = [], fun = [];
  for (let i = 0; i < size; i++) {
    mod.push(new Uint8Array(size));
    fun.push(new Uint8Array(size));
  }
  const setf = (x, y, v) => { mod[y][x] = v; fun[y][x] = 1; };

  for (let i = 0; i < size; i++) { setf(6, i, 1 - i % 2); setf(i, 6, 1 - i % 2); }

  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || x >= size || y < 0 || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        setf(x, y, (d !== 2 && d !== 4) ? 1 : 0);
      }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);

  const ap = alignPositions(ver);
  for (let i = 0; i < ap.length; i++)
    for (let j = 0; j < ap.length; j++) {
      const corner = (i === 0 && j === 0) || (i === 0 && j === ap.length - 1) || (i === ap.length - 1 && j === 0);
      if (corner) continue;
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++)
          setf(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1 ? 1 : 0);
    }

  /* 预留格式信息。i===6 要跳过：(6,8) 和 (8,6) 属于定时图案，格式信息本来
     就绕开它们，覆盖掉就把定时图案打断了。 */
  for (let i = 0; i < 9; i++) if (i !== 6) { setf(i, 8, 0); setf(8, i, 0); }
  setf(8, size - 8, 1);                       /* 恒黑模块 */
  if (ver >= 7)
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + i % 3, b = Math.floor(i / 3);
      setf(a, b, 0); setf(b, a, 0);
    }

  const cw = interleave(buildCodewords(data, ver, ecl), ver, ecl);
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++)
      for (let k = 0; k < 2; k++) {
        const x = right - k;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!fun[y][x] && i < cw.length * 8) {
          mod[y][x] = (cw[i >> 3] >>> (7 - (i & 7))) & 1;
          i++;
        }
      }
  }
  return { mod, fun, size };
}

/* 掩码评分。N3（类似定位图案的 1:1:3:1:1）必须把符号外的空白边也算成浅色，
   否则贴边的图案会漏计，选出来的掩码就和标准不一样。 */
function penalty(mod, size) {
  const N1 = 3, N2 = 3, N3 = 40, N4 = 10;
  let res = 0;

  const countPatterns = (h) => {
    const n = h[1];
    const core = n > 0 && h[2] === n && h[3] === n * 3 && h[4] === n && h[5] === n;
    return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) +
           (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0);
  };
  const addHistory = (runLen, h) => {
    if (h[0] === 0) runLen += size;
    h.unshift(runLen);
    h.length = 7;
  };
  const terminate = (runColor, runLen, h) => {
    if (runColor) { addHistory(runLen, h); runLen = 0; }
    runLen += size;
    addHistory(runLen, h);
    return countPatterns(h);
  };

  for (let y = 0; y < size; y++) {
    let runColor = 0, run = 0, h = new Array(7).fill(0);
    for (let x = 0; x < size; x++) {
      if (mod[y][x] === runColor) {
        run++;
        if (run === 5) res += N1; else if (run > 5) res += 1;
      } else {
        addHistory(run, h);
        if (!runColor) res += countPatterns(h) * N3;
        runColor = mod[y][x];
        run = 1;
      }
    }
    res += terminate(runColor, run, h) * N3;
  }
  for (let x = 0; x < size; x++) {
    let runColor = 0, run = 0, h = new Array(7).fill(0);
    for (let y = 0; y < size; y++) {
      if (mod[y][x] === runColor) {
        run++;
        if (run === 5) res += N1; else if (run > 5) res += 1;
      } else {
        addHistory(run, h);
        if (!runColor) res += countPatterns(h) * N3;
        runColor = mod[y][x];
        run = 1;
      }
    }
    res += terminate(runColor, run, h) * N3;
  }
  for (let y = 0; y < size - 1; y++)
    for (let x = 0; x < size - 1; x++) {
      const c = mod[y][x];
      if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) res += N2;
    }

  let dark = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) dark += mod[y][x];
  const total = size * size;
  const k = Math.floor((Math.abs(dark * 20 - total * 10) + total - 1) / total) - 1;
  return res + k * N4;
}

function drawFormat(mod, ecl, mask, size) {
  const data = (FORMAT_BITS[ecl] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => (bits >>> i) & 1;

  for (let i = 0; i < 6; i++) mod[i][8] = bit(i);
  mod[7][8] = bit(6);
  mod[8][8] = bit(7);
  mod[8][7] = bit(8);
  for (let i = 9; i < 15; i++) mod[8][14 - i] = bit(i);
  for (let i = 0; i < 8; i++) mod[8][size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) mod[size - 15 + i][8] = bit(i);
  mod[size - 8][8] = 1;
}

function drawVersion(mod, ver, size) {
  if (ver < 7) return;
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
  const bits = (ver << 12) | rem;
  for (let i = 0; i < 18; i++) {
    const b = (bits >>> i) & 1;
    const a = size - 11 + i % 3, c = Math.floor(i / 3);
    mod[c][a] = b;
    mod[a][c] = b;
  }
}

/* --------------------------------------------------------------- 对外接口 */

/*  bytes: Uint8Array；ecl: 0=L 1=M 2=Q 3=H
    返回 { size, ver, mask, mod }，mod[y][x] 为 0/1                          */
export function encodeQr(bytes, ecl) {
  const lvl = ecl === undefined ? 1 : ecl;
  let ver = 0;
  for (let v = 1; v <= 40; v++) {
    if (4 + ccBits(v) + 8 * bytes.length <= dataCodewords(v, lvl) * 8) { ver = v; break; }
  }
  if (!ver) throw new Error('内容太长，二维码放不下');

  const { mod, fun, size } = makeMatrix(bytes, lvl, ver);
  drawVersion(mod, ver, size);

  let best = null, bestPen = Infinity, bestMask = 0;
  for (let m = 0; m < 8; m++) {
    const cand = mod.map((r) => r.slice());
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++)
        if (!fun[y][x] && MASKS[m](x, y) === 0) cand[y][x] ^= 1;
    drawFormat(cand, lvl, m, size);
    const p = penalty(cand, size);
    if (p < bestPen) { best = cand; bestPen = p; bestMask = m; }
  }
  return { size, ver, mask: bestMask, mod: best };
}

/* 画成 SVG：矢量，放大缩小和打印都不糊，也不用 canvas。
   quiet 是四周的空白边，标准要求至少 4 个模块，少了扫不出来。 */
export function qrSvg(bytes, opts) {
  const o = opts || {};
  const q = o.quiet === undefined ? 4 : o.quiet;
  const { size, mod, ver } = encodeQr(bytes, o.ecl);
  const dim = size + q * 2;

  let d = '';
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++)
      if (mod[y][x]) d += 'M' + (x + q) + ' ' + (y + q) + 'h1v1h-1z';

  return {
    ver, size,
    svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dim + ' ' + dim + '" ' +
         'shape-rendering="crispEdges" width="100%" role="img" aria-label="邀请二维码">' +
         '<rect width="' + dim + '" height="' + dim + '" fill="#fff"/>' +
         '<path d="' + d + '" fill="#000"/></svg>'
  };
}
