const SW_VERSION = 'yb579-sw-v1';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// 保持最小行为：不做离线缓存拦截，避免影响登录/API
self.addEventListener('fetch', () => {});
