/**
 * Theme Toggle — Dark / Light Mode
 */
(function () {
  const STORAGE_KEY = 'codeshield_theme';
  const body = document.getElementById('body') || document.body;

  // Load saved preference
  const saved = localStorage.getItem(STORAGE_KEY);
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  let isDark = saved !== null ? saved === 'dark' : prefersDark !== false;

  function applyTheme(dark) {
    body.classList.toggle('dark-mode', dark);
    body.classList.toggle('light-mode', !dark);
    // Notify other scripts (e.g. CodeMirror theme swap)
    window.dispatchEvent(new CustomEvent('themeChanged', { detail: { dark } }));
    // Update toggle button icon
    document.querySelectorAll('[onclick="toggleTheme()"]').forEach(btn => {
      btn.textContent = dark ? '🌙' : '☀️';
    });
  }

  window.toggleTheme = function () {
    isDark = !isDark;
    localStorage.setItem(STORAGE_KEY, isDark ? 'dark' : 'light');
    applyTheme(isDark);
  };

  // Apply on load
  applyTheme(isDark);
})();
