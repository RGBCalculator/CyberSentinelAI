# Extension Typography & Local Font Assets

This directory is reserved for hosting locally bundled font files (`.woff2`, `.woff`) for the CyberSentinel AI browser extension.

## Purpose & CSP Compliance

- Manifest V3 Content Security Policy (CSP) restricts loading external resources from remote CDNs (such as Google Fonts).
- In future sprints, the **Inter** and **Outfit** typeface families will be stored as local static assets within this directory.
- Until local font bundles are integrated, the extension utilizes a robust, native system font stack: `Inter, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`.

> **Note**: Documentation only. No font files are bundled in this sprint.
