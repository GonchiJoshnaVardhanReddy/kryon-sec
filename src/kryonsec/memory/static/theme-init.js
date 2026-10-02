/* Set the theme before first paint.
 *
 * Byte-for-byte the same logic as the landing page's theme-init.js: the same
 * localStorage key and the same data-theme attribute, so the two surfaces
 * agree on which mode you last chose. Light is the default; dark is opt-in.
 */
try {
    if (localStorage.getItem('kryonsec-theme') === 'dark') {
        document.documentElement.dataset.theme = 'dark';
    }
} catch (_) {}
