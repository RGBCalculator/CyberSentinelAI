# CyberSentinel AI Chrome Extension — Architecture & Developer Documentation

## Project Overview

**CyberSentinel AI** is an enterprise-grade cybersecurity platform engineered to protect organizations against advanced phishing, zero-day credential harvesting, and web-based social engineering attacks. The CyberSentinel AI browser extension serves as the frontline client sensor—inspecting DOM structures, monitoring sensitive input fields, and leveraging real-time backend AI threat intelligence to evaluate webpages.

This document outlines the architectural blueprint, folder organization, coding standards, and development workflows for the Chrome extension, built on **Manifest V3**.

---

## Architecture Philosophy

The CyberSentinel AI browser extension architecture adheres to five core software engineering principles:

1. **Clear Separation of Concerns**: Each directory and module has an explicit, bounded responsibility. UI layers (`popup/`), background orchestration (`background/`), DOM inspection (`content/`), network communication (`api/`), and cross-cutting domain definitions (`shared/`, `types/`) are strictly decoupled.
2. **Enterprise Modularity & Scalability**: Designed to scale from a lightweight sensor into an enterprise security client without structural refactoring. Shared constants, interfaces, models, and validators eliminate code duplication and enforce contract consistency.
3. **Zero-Trust Input & IPC Validation**: All inter-process communication (IPC) messages between content scripts, the background service worker, and the popup UI must be verified using schema validators before processing.
4. **Manifest V3 Compliance**: Fully non-persistent event-driven background execution using service workers, declarative content scripts, and modern browser storage APIs.
5. **Future-Proofing & React Readiness**: The `popup/` component and layout boundaries are structured so that migrating from vanilla HTML/CSS/JS to a component-driven framework (such as React or Preact) requires zero changes to the underlying `api/`, `shared/`, or `background/` layers.

---

## Folder Structure

```
browser-extension/
│
├── manifest.json
│
├── popup/
│   ├── components/
│   │   └── README.md
│   ├── layouts/
│   │   └── README.md
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
│
├── background/
│   ├── service-worker.js
│   └── README.md
│
├── content/
│   ├── content.js
│   └── README.md
│
├── api/
│   ├── api.js
│   └── README.md
│
├── utils/
│   ├── constants.js
│   ├── helpers.js
│   └── README.md
│
├── shared/
│   ├── constants/
│   ├── enums/
│   ├── interfaces/
│   ├── models/
│   └── validators/
│
├── types/
│   └── scan-response.md
│
├── assets/
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   ├── images/
│   ├── fonts/
│   ├── animations/
│   └── styles/
│
└── README.md
```

---

## Responsibilities of Every Folder

| Folder / Module | Responsibility |
| :--- | :--- |
| `manifest.json` | Manifest V3 extension configuration defining permissions, background service worker, content script rules, and action icons. |
| `popup/` | User interface presented when clicking the toolbar icon. Contains HTML/CSS/JS, reusable component specs (`components/`), and page layouts (`layouts/`). |
| `background/` | Manifest V3 event-driven service worker (`service-worker.js`) responsible for lifecycle events, badge updates, context menus, notifications, and IPC routing. |
| `content/` | Content scripts (`content.js`) injected into webpages for DOM analysis, metadata extraction, form/login detection, and warning banner overlays. |
| `api/` | Client HTTP layer (`api.js`) for communicating with CyberSentinel AI backend services, handling authentication, and managing scan endpoints. |
| `utils/` | Stateless, reusable utility helpers (`helpers.js`, `constants.js`) for URL parsing, data formatting, browser storage wrappers, and date manipulation. |
| `shared/` | Shared domain artifacts used across extension layers: `constants/`, `enums/`, `interfaces/`, `models/`, and `validators/`. |
| `types/` | API contract documentation and data schema specifications (e.g., `scan-response.md`). |
| `assets/` | Static media assets including application icons (`icons/`), images (`images/`), typography (`fonts/`), animations (`animations/`), and shared styles (`styles/`). |

---

## Coding Standards

1. **Language Standard**: Modern ECMAScript (ES2022+). Prefer `async`/`await` over raw callback chains or unhandled Promise chains.
2. **Immutability & Pure Functions**: Utility functions and data transformers must be pure and stateless. Never mutate shared objects directly.
3. **Error Handling**: All asynchronous network calls and Chrome Extension API invocations must be wrapped in structured `try`/`catch` blocks with graceful fallback behavior.
4. **Documentation**: Every module, class, and exported function must contain JSDoc annotations outlining parameter types, return values, and possible thrown errors.
5. **Security**: Never use `eval()`, `new Function()`, or inline event handlers (`onclick=...`). Do not insert untrusted DOM content using `.innerHTML`; use `.textContent` or safe DOM creation methods.

---

## Naming Conventions

- **File & Directory Names**: Kebab-case (`service-worker.js`, `scan-response.md`, `threat-card.js`).
- **Classes & Models**: PascalCase (`ThreatReport`, `ScanHistoryEntry`, `ApiClient`).
- **Functions & Methods**: CamelCase (`scanURL`, `reportFalsePositive`, `extractFormMetadata`).
- **Constants & Enums**: UPPER_SNAKE_CASE (`MAX_RETRY_ATTEMPTS`, `THREAT_SEVERITY_CRITICAL`).
- **Interfaces / Type Definitions**: PascalCase with descriptive suffixes (`ScanResponse`, `AuthCredentials`, `HealthStatus`).

---

## Manifest V3 Notes

- **No Background Pages**: Background scripts run as a non-persistent Service Worker (`service-worker.js`). Do not store long-lived state in global memory variables; use `chrome.storage.local` or `chrome.storage.session`.
- **Content Security Policy (CSP)**: The Manifest V3 CSP strictly disallows remote script execution and inline scripts. All scripts must be bundled locally within the extension directory.
- **Declarative Net Request**: Network interception or ad-hoc header modification must utilize `chrome.declarativeNetRequest` rules rather than blocking webRequest listeners.

---

## Development Workflow

1. **Branching**: Develop features in isolated topic branches created off `develop` (e.g., `feature/popup-threat-card`, `fix/url-normalizer`).
2. **Linting & Type Checking**: Run static analysis and linter checks prior to submitting pull requests. Ensure no JSDoc or type violations exist.
3. **No Breaking Refactors**: When expanding functionality in future sprints, extend existing directories rather than altering the foundational directory tree.

---

## Chrome Loading Instructions

To load the CyberSentinel AI extension locally in Google Chrome for development and verification:

1. Open Google Chrome and navigate to **`chrome://extensions/`** in the address bar.
2. Enable **Developer mode** using the toggle switch in the top right corner.
3. Click the **Load unpacked** button in the top left toolbar.
4. Select the absolute filesystem folder:  
   `c:\Users\hp\CyberSentinelAI\browser-extension`
5. The CyberSentinel AI extension will appear in your installed extensions list and toolbar. Whenever you modify files during Sprint 2+, click the **Reload** icon on the extension card.

---

## Future Roadmap

- **Sprint 2 — Manifest & Popup Implementation**: Configure full `manifest.json` permissions and implement modular popup layouts and components.
- **Sprint 3 — Service Worker & IPC Router**: Implement message passing, periodic caching alarms, and badge state synchronization in `background/service-worker.js`.
- **Sprint 4 — Content Script Sensors**: Add DOM login detection, sensitive input field monitoring, and warning banner overlays in `content/content.js`.
- **Sprint 5 — Backend Integration**: Wire `api/api.js` to CyberSentinel AI live backend endpoints (`/api/v1/scan`, `/api/v1/feedback`).

---

## Migration Strategy (React / Enterprise Frameworks)

If the popup UI complexity requires a framework migration (such as React + Vite):
1. Create a build toolchain targeting `popup/` as the HTML/JS bundle entry point.
2. Replace vanilla HTML/JS components inside `popup/components/` and `popup/layouts/` with `.jsx`/`.tsx` components without altering `api/`, `shared/`, or `types/`.
3. Configure the bundler to output compiled artifacts directly into `popup/dist/` or retain the standard path names so `manifest.json` requires zero modifications.

---

## Testing Strategy

- **Unit Testing**: Write unit tests for all functions in `utils/` and domain models in `shared/models/` and `shared/validators/` using Jest or Vitest.
- **API & Mocking**: Mock `chrome.*` API endpoints using `jest-chrome-mock` or equivalent utilities for deterministic service worker and content script testing.
- **End-to-End (E2E)**: Use Puppeteer or Playwright with Chrome extension support to test popup interaction flows, warning overlays, and real DOM signal extraction.

---

## Contribution Guidelines

1. **Zero Logic in Arch Sprints**: Architectural and structural sprints must never introduce untested implementation stubs or placeholder business logic.
2. **Preserve Compatibility**: Every new module or folder must be documented with a `README.md` explaining its purpose before adding implementation files.
3. **Code Reviews**: Every pull request must be reviewed by at least one Principal/Senior Engineer to ensure adherence to enterprise security principles and clean architecture.
