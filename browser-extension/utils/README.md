# Extension Utilities Documentation

This directory contains generic, reusable utility functions and helper modules that support operations across popup UI scripts, background service workers, and content scripts.

## Planned Utilities

The following helper categories and utilities are planned for future development:

### URL Helpers
- Normalizing URLs, stripping tracking parameters, extracting hostnames/origins, and detecting top-level domains.
- Checking against internal browser schemes (`chrome://`, `about:`, `file://`) to prevent scanning unsupported tabs.

### Validation Helpers
- Input string validation, regex matchers for domain formats, IP addresses, and email signatures.
- Guarding against malformed DOM attributes or injected payload structures.

### Formatting Helpers
- Transforming raw threat scores into readable percentages and severity labels.
- Truncating long URL strings and formatting evidence lists for UI presentation.

### Storage Helpers
- Wrappers around `chrome.storage.local` and `chrome.storage.sync` with type safety, caching TTL, and default fallbacks.
- Managing local threat cache and enterprise user preferences.

### Date Helpers
- Formatting UTC timestamps into relative human-readable strings (e.g., `"2 minutes ago"`, `"Today at 14:30"`).
- Determining expiration intervals for cached scan decisions and auth tokens.

> **Note**: This directory currently holds initial skeleton files (`constants.js`, `helpers.js`). No utility logic is implemented in this sprint.
