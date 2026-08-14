/* Service worker.
 *
 * Strategy: network-first for code (HTML/JS/manifest), cache-first for icons.
 * The whole shell is ~15 KB, so always trying the network costs almost nothing
 * and guarantees a code change reaches the phone on the next launch. The cache
 * exists purely so the app still opens with no connection.
 *
 * Ciphertext (brief-*.json) is never handled here — app.js keeps its own
 * per-market copy in IndexedDB, which is the real offline fallback.
 *
 * Versioning: v<major>.<minor>，**minor 只取 0–9**
 *   每次改动 minor +1；到 9 之后进位到下一个 major，即 4.9 -> 5.0
 *   不出现 4.10 这种两位数 minor
 * 改任何外壳文件都必须同时递增 sw.js 的 CACHE 与 app.js 的 APP_VERSION，
 * 否则手机会继续用旧缓存。
 */
const CACHE = "brief-v6.7";
const SHELL = ["./stock.html", "./app.js", "./manifest.json",
               "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: "reload" }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET") return;
  if (/brief-(us|cn)\.json$/.test(url.pathname)) return;   // handled by app.js
  // 上行会话密钥：**绝不缓存**。手机提交指令前要靠它拿到当前 kid，
  // 缓存一份旧的会让 kid 落后，虽然 keyring 留了 5 把兜底，但没必要自找麻烦。
  if (/inbox-(key|token)\.json$/.test(url.pathname)) return;
  if (url.pathname.startsWith("/ipa/")) return;             // 按需接口从不缓存
  if (url.origin !== self.location.origin) return;         // GitHub raw/API fallbacks

  const isIcon = /\.png$/.test(url.pathname);

  if (isIcon) {
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
    return;
  }

  // network-first: code changes land on the next launch
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true })
        .then((hit) => hit || caches.match("./stock.html")))
  );
});

// allow the page to force an immediate takeover
self.addEventListener("message", (e) => {
  if (e.data === "skipWaiting") self.skipWaiting();
});
