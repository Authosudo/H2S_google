/* Synchronous pre-paint theme initializer to prevent theme flashing (FOUC) */
(function () {
  var theme = 'light';
  try {
    var raw = localStorage.getItem('pii_sentinel_ui_settings');
    if (raw) {
      var parsed = JSON.parse(raw);
      if (parsed && (parsed.theme === 'dark' || parsed.theme === 'light')) {
        theme = parsed.theme;
      } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        theme = 'dark';
      }
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      theme = 'dark';
    }
  } catch (_) {
    if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      theme = 'dark';
    }
  }
  document.documentElement.setAttribute('data-theme', theme);
})();
