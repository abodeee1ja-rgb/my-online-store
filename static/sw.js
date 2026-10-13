// Service worker بسيط: يخزّن الملفات الثابتة، ويجرّب الشبكة أولاً للصفحات.
const CACHE = "souqna-v2";
const STATIC = ["/static/style.css", "/static/icon.svg", "/static/icon-192.png"];
const OFFLINE_HTML =
  '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<body style="font-family:sans-serif;text-align:center;padding:60px 20px">' +
  '<div style="font-size:3rem">📡</div><h2>ما أكو إنترنت</h2>' +
  "<p>تأكد من اتصالك وحاول مرة ثانية.</p></body></html>";

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(STATIC)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  // الملفات الثابتة: من الكاش أولاً مع تحديث بالخلفية
  if (url.pathname.startsWith("/static/")) {
    e.respondWith(
      caches.match(req).then((hit) => {
        const net = fetch(req)
          .then((res) => {
            if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
            return res;
          })
          .catch(() => hit);
        return hit || net;
      })
    );
    return;
  }

  // الصفحات: الشبكة أولاً (حتى تبقى الأسعار والمخزون حديثة)
  if (req.mode === "navigate") {
    e.respondWith(
      fetch(req).catch(() => new Response(OFFLINE_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } }))
    );
  }
});
