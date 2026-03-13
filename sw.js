// MCC Service Worker — Signal Flip Notifications
const CACHE_NAME = 'mcc-sw-v1';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(self.clients.claim());
});

// Listen for messages from the dashboard
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SIGNAL_FLIP') {
    const { asset, signal, color } = e.data;
    const title = `${asset} — ${signal === 1 ? '▲ LONG' : '▼ SHORT'}`;
    const body  = signal === 1
      ? `${asset} hat auf LONG gewechselt`
      : `${asset} hat auf SHORT gewechselt`;

    self.registration.showNotification(title, {
      body,
      icon:  '/icon-192.png',
      badge: '/icon-192.png',
      tag:   `mcc-flip-${asset}`,
      renotify: true,
      vibrate: [200, 100, 200],
      data: { asset, signal },
    });
  }
});

// Click on notification → focus or open the dashboard tab
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      for (const c of clients) {
        if (c.url && c.focus) { c.focus(); return; }
      }
      if (self.clients.openWindow) self.clients.openWindow('/');
    })
  );
});
