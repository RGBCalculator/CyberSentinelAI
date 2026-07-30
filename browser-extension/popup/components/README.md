# Popup UI Components

This directory is reserved for reusable, modular UI components used inside the CyberSentinel AI browser extension popup interface.
Do not place layout or full-page view wrappers here; use `../layouts/` instead.

## Future Reusable Components

The following reusable UI components are planned for future sprint implementations:

- **Threat Card**: Displays detailed information about a detected security threat, including severity, category, and source.
- **Evidence Card**: Summarizes technical forensic evidence, suspicious scripts, network requests, or DOM signatures discovered on the page.
- **Recommendation Card**: Provides actionable remediation advice or safety guidelines for the user based on scan analysis.
- **Risk Meter**: Visual gauge or indicator representing the aggregate threat score and confidence level of the current page.
- **Loading Indicator**: Feedback spinner or progress bar displayed while background scans and backend analyses are in progress.
- **Status Badge**: Compact visual badge indicating overall security status (e.g., Safe, Suspicious, Dangerous, Offline).
- **Scan Summary**: Overview banner summarizing total scanned items, timestamps, and detection verdicts.

> **Note**: This sprint is strictly for architecture and directory structure. No component implementation logic is included yet.
