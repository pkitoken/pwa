/* =========================================================================
   仓库访问层 —— 私有 GitHub 仓库当存储用，加上本机 IndexedDB 键值表。

   为什么用 Git Data API 而不是省事的 Contents API：
   ---------------------------------------------------------------------
   · Contents API 一次只能改一个文件，「上传密文」和「更新索引」会变成两次
     提交，中间断网就留下孤儿文件或指向空气的索引条目。
   · Git Data API 可以把密文和新索引放进同一棵树、同一个提交，一次推上去，
     要么全成要么全不成。
   · 推分支引用时不加 force，GitHub 就只接受快进更新。别人抢先提交了，我们
     这次必然被拒（422），于是重读、重算、重推——十个人同时发文件也不会互相
     覆盖索引。这就是这层唯一的并发控制，简单且够用。
   ========================================================================= */

const API = 'https://api.github.com';

/* --------------------------------------------------------------- 本机存储 */

const DB_NAME = 'xfer';
const DB_STORE = 'kv';
let dbp = null;

function db() {
  if (!dbp) {
    dbp = new Promise((res, rej) => {
      const r = indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(DB_STORE);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  return dbp;
}

export async function kvGet(key) {
  const d = await db();
  return new Promise((res, rej) => {
    const r = d.transaction(DB_STORE, 'readonly').objectStore(DB_STORE).get(key);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

export async function kvSet(key, val) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(DB_STORE, 'readwrite');
    t.objectStore(DB_STORE).put(val, key);
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
  });
}

export async function kvDel(key) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(DB_STORE, 'readwrite');
    t.objectStore(DB_STORE).delete(key);
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
  });
}

export async function kvClear() {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(DB_STORE, 'readwrite');
    t.objectStore(DB_STORE).clear();
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
  });
}

/* --------------------------------------------------------------- HTTP 底层 */

function headers(cfg, accept) {
  return {
    'Authorization': 'Bearer ' + cfg.token,
    'Accept': accept || 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
}

const base = (cfg) => API + '/repos/' + cfg.owner + '/' + cfg.repo;

async function fail(res) {
  let detail = '';
  try { detail = (await res.json()).message || ''; } catch {}
  const map = {
    401: '令牌无效或已过期',
    403: '令牌权限不足，或触发了速率限制',
    404: '仓库或路径不存在——也可能是令牌看不到这个私有仓库',
    409: '仓库状态冲突',
    422: '提交被拒绝'
  };
  const err = new Error((map[res.status] || ('HTTP ' + res.status)) + (detail ? '：' + detail : ''));
  err.status = res.status;
  return err;
}

async function api(cfg, path, opts) {
  const o = opts || {};
  let res;
  try {
    res = await fetch(base(cfg) + path, {
      method: o.method || 'GET',
      headers: Object.assign(headers(cfg, o.accept), o.body ? { 'Content-Type': 'application/json' } : {}),
      body: o.body ? JSON.stringify(o.body) : undefined,
      cache: 'no-store'
    });
  } catch (e) {
    /* Safari 把所有网络失败都说成 “Load failed”，中文界面里显示「载入失败」，
       看着像是应用坏了。换成一句说得清的。 */
    throw new Error('连不上 GitHub——检查网络；如果刚才在存文件，可能是页面跳转把请求打断了');
  }
  if (!res.ok) throw await fail(res);
  return o.raw ? new Uint8Array(await res.arrayBuffer()) : res.json();
}

/* ------------------------------------------------------------------ 读取 */

export async function probe(cfg) {
  const r = await api(cfg, '');
  return {
    private: r.private,
    push: !!(r.permissions && r.permissions.push),
    branch: r.default_branch,
    /* size 是 GitHub 自己报的仓库占用（KB），**含 git 历史**——删过的密文
       也还算在里面。正因如此它才是判断「该压平历史了」的那个数。 */
    sizeKb: r.size || 0,
    pushedAt: r.pushed_at || null
  };
}

/* 列一个目录。用来数 blobs/ 里到底有多少文件、有没有没人引用的孤儿。
   一次调用就够，不用逐层遍历。 */
export async function list(cfg, path, ref) {
  const url = '/contents/' + path.split('/').map(encodeURIComponent).join('/') +
              '?ref=' + encodeURIComponent(ref || cfg.branch);
  try {
    const r = await api(cfg, url);
    return Array.isArray(r) ? r : [];
  } catch (e) {
    if (e.status === 404) return [];
    throw e;
  }
}

/* Contents API 加 raw 媒体类型，最大能直接取回 100 MB，不必先查 blob sha。 */
export async function readBytes(cfg, path, ref) {
  const url = '/contents/' + path.split('/').map(encodeURIComponent).join('/') +
              '?ref=' + encodeURIComponent(ref || cfg.branch);
  try {
    return await api(cfg, url, { accept: 'application/vnd.github.raw', raw: true });
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

export async function readJson(cfg, path, ref) {
  const b = await readBytes(cfg, path, ref);
  if (!b) return null;
  return JSON.parse(new TextDecoder().decode(b));
}

async function head(cfg) {
  const ref = await api(cfg, '/git/ref/heads/' + encodeURIComponent(cfg.branch));
  const commit = await api(cfg, '/git/commits/' + ref.object.sha);
  return { commit: ref.object.sha, tree: commit.tree.sha };
}

/* ------------------------------------------------------------------ 写入 */

/*  fn(index, ctx) 返回 null 表示无需改动，否则返回：
      { message, index, puts: [{path, b64}], dels: [path] }
    ctx.read(path) 读同一个提交上的别的 JSON 文件（领取记录就靠它做
    读-改-写）。fn 每次重试都会拿到最新状态重新计算，所以它必须是幂等的。 */
export async function transact(cfg, fn) {
  let lastErr = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    const h = await head(cfg);
    const index = (await readJson(cfg, 'index.json', h.commit)) || { v: 1, entries: [] };
    const plan = await fn(index, {
      commit: h.commit,
      read: (path) => readJson(cfg, path, h.commit)
    });
    if (!plan) return null;

    const tree = [];
    for (const p of plan.puts || []) {
      const blob = await api(cfg, '/git/blobs', {
        method: 'POST', body: { content: p.b64, encoding: 'base64' }
      });
      tree.push({ path: p.path, mode: '100644', type: 'blob', sha: blob.sha });
    }
    if (plan.index) {
      const body = JSON.stringify(plan.index, null, 1);
      const blob = await api(cfg, '/git/blobs', { method: 'POST', body: { content: body, encoding: 'utf-8' } });
      tree.push({ path: 'index.json', mode: '100644', type: 'blob', sha: blob.sha });
    }
    /* sha:null 就是「从树里删掉这条」，删密文靠的就是它 */
    for (const d of plan.dels || []) tree.push({ path: d, mode: '100644', type: 'blob', sha: null });

    /* 删除项要求路径在 base_tree 里真的存在。要是别的客户端刚好抢先删掉了
       同一个 blob，这里会 422；那就退一步只提交索引，让密文变成孤儿——夜里
       的清理任务会把没人引用的 blob 收走。总比整个事务卡死强。 */
    let newTree;
    try {
      newTree = await api(cfg, '/git/trees', { method: 'POST', body: { base_tree: h.tree, tree } });
    } catch (e) {
      if (e.status !== 422 || !(plan.dels || []).length) throw e;
      const dels = new Set(plan.dels);
      newTree = await api(cfg, '/git/trees', {
        method: 'POST',
        body: { base_tree: h.tree, tree: tree.filter((t) => !(t.sha === null && dels.has(t.path))) }
      });
    }
    const commit = await api(cfg, '/git/commits', {
      method: 'POST', body: { message: plan.message, tree: newTree.sha, parents: [h.commit] }
    });

    try {
      await api(cfg, '/git/refs/heads/' + encodeURIComponent(cfg.branch), {
        method: 'PATCH', body: { sha: commit.sha, force: false }
      });
      return plan;
    } catch (e) {
      /* 非快进 = 有人抢先提交了。退避一下，重头再来一遍。 */
      if (e.status !== 422 && e.status !== 409) throw e;
      lastErr = e;
      await new Promise((r) => setTimeout(r, 300 + attempt * 400 + Math.floor(Math.random() * 300)));
    }
  }
  throw new Error('仓库连续 6 次被别人抢先提交，请稍后再试' + (lastErr ? '（' + lastErr.message + '）' : ''));
}
