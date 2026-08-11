/* Service worker — versioned shell cache with automatic updates.
 *
 * RELEASING: bump VERSION below. That is the only edit required.
 * Changing it changes this file's bytes, which is what makes the browser
 * treat the worker as new; the new version then precaches a fresh copy of
 * every shell file under a new cache name and deletes the old cache.
 */

const VERSION = '1.4';
const CACHE = `ledclock-${VERSION}`;

const SHELL = [
  './',
  'index.html',
  'styles.css',
  'app.js',
  'manifest.json',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/icon-maskable-512.png',
  'icons/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // cache:'reload' bypasses the HTTP cache, so a release can never precache
    // stale bytes that a CDN or the browser is still holding.
    await cache.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k.startsWith('ledclock-') && k !== CACHE)
          .map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

/* Cache-first within a version. Each release precaches its own complete set at
   install time, so a hit is always the right bytes for this version. */
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
