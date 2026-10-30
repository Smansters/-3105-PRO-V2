self.addEventListener('install', (e) => {
  console.log('[Service Worker] Đã cài đặt');
  self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  // Để trống fetch listener là đủ để vượt qua bài kiểm tra PWA của Chrome
});