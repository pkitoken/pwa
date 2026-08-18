/* Service worker —— 带版本号的外壳缓存，自动更新。
 *
 * 发布时：改下面的 VERSION，这是唯一必须改的地方。
 * 改了它这个文件的字节就变了，浏览器才会认为 worker 是新的；新版本随即用
 * 新的缓存名重新预缓存全部外壳文件，并删掉旧缓存。不改版本号，装过的手机
 * 会一直吃旧的 app.js，推什么上去都没用。
 */

const VERSION = '1.10';
const CACHE = `xfer-${VERSION}`;

const SHELL = [
  './',
  'index.html',
  'styles.css',
  'app.js',
  'crypto.js',
  'store.js',
  'invite.js',
  'qr.js',
  'manifest.json',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/icon-maskable-512.png',
  'icons/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // cache:'reload' 绕开 HTTP 缓存，保证一次发布不会把陈旧字节预缓存进来
    await cache.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k.startsWith('xfer-') && k !== CACHE)
          .map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

/* 同一版本内缓存优先。跨域请求（api.github.com）直接放行——密文和令牌
   绝不能进缓存。 */
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== location.origin) return;

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(req, { ignoreSearch: true });
    if (hit) return hit;

    try {
      const res = await fetch(req);
      if (res && res.ok && res.type === 'basic') cache.put(req, res.clone());
      return res;
    } catch {
      if (req.mode === 'navigate') {
        const shell = await cache.match('index.html');
        if (shell) return shell;
      }
      return Response.error();
    }
  })());
});

self.addEventListener('message', (e) => {
  const msg = e.data || {};
  if (msg.type === 'VERSION' && e.ports && e.ports[0]) e.ports[0].postMessage(VERSION);
  if (msg.type === 'SKIP_WAITING') self.skipWaiting();
});
