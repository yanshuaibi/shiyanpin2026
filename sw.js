// NEXUS Service Worker
// 只缓存"外壳"（index.html + 图标），从不缓存 Supabase 接口请求，
// 保证数据始终是最新的，同时让 App 在弱网/离线时至少能打开界面。

const CACHE_NAME = 'nexus-shell-v1';
const SHELL_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // 跨域请求（Supabase API、图标搜索等）一律直接走网络，绝不缓存
  if (url.origin !== self.location.origin) return;

  // 只对页面导航和外壳文件做"网络优先，失败回退缓存"
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, resClone));
        return res;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match('./index.html')))
  );
});
