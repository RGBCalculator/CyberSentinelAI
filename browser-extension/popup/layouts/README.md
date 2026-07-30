# Popup Layouts

This directory is reserved for high-level structural layouts and view containers that orchestrate components inside the CyberSentinel AI extension popup.

## Future Layouts

The following layout views are planned for future sprint implementations:

- **Default Scan Layout**: Primary active interface presented when a user opens the popup on a standard, supported web page. Combines the status badge, risk meter, scan summary, and interactive threat cards.
- **Error Layout**: Fallback interface displayed when a background scan fails, network connectivity is lost, or backend authentication expires. Provides clear error messaging and retry actions.
- **Unsupported Page Layout**: Layout shown when the current tab is an internal browser page (e.g., `chrome://`), local file, or restricted origin where scanning is not applicable or permitted.

> **Note**: This sprint is strictly for architecture and directory structure. No layout implementation logic is included yet.
