# Content Script Documentation

This directory contains content scripts (`content.js`) that execute within the context of target web pages inspected by CyberSentinel AI.

## Future Responsibilities

Content scripts bridge target webpage DOM inspection with the secure background service worker. In future sprints, the content script layer will handle:

### DOM Analysis
- Scanning page structure, hidden iframes, external script origins, and obfuscated JavaScript elements for suspicious patterns.
- Detecting credential harvesting signatures and zero-day phishing indicators.

### Page Metadata Extraction
- Inspecting page title, meta tags, Open Graph properties, canonical URLs, and SSL/TLS context indicators to support AI threat scoring.

### Form Detection
- Monitoring `<form>` elements and dynamic form submissions across web applications.
- Identifying form action endpoints that deviate from the host origin or submit credentials over unencrypted connections.

### Login Detection
- Identifying authentication portals, SSO login forms, and password-recovery pages to provide elevated monitoring and zero-trust verification.

### Sensitive Input Detection
- Detecting password inputs (`<input type="password">`), credit card fields, API key textareas, and other PII input fields.
- Preventing accidental disclosure of credentials on unverified or malicious domains.

### Warning Banner Overlay
- Injecting high-visibility, non-intrusive DOM warning overlays or blocking banners when a site is determined to be malicious by the backend AI engine.
- Allowing safe navigation away from threat sites with a single click.

> **Note**: This sprint is strictly for architectural structure and documentation. No content script DOM manipulation or analysis logic is implemented yet.
