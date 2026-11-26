// The theme is the HSL Suite's: hsl-ui/suite.js (loaded just before this) applies it before the first paint,
// light unless the user turned dark mode on in the user menu. Nothing stored means light; the operating
// system's setting is never followed. Slipway kept its own choice under "slipway-theme" before: move it over once.
(function () {
  if (window.HSLSuite) window.HSLSuite.theme.migrate(["slipway-theme"]);
})();
