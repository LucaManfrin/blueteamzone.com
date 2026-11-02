(function () {
  // Runs before paint to avoid a flash of the wrong theme.
  // Default is dark; a "theme" cookie (1h expiry) overrides it.
  var match = document.cookie.match(/(?:^|; )theme=(dark|light)/);
  var theme = match ? match[1] : 'dark';
  if (theme === 'dark') document.documentElement.classList.add('dark');
})();