// External module so the pre-render theme also respects script-src self.
try {
  if (localStorage.getItem('lexflow-theme') === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  }
} catch { /* storage can be disabled without preventing app startup */ }
