# Shared Interfaces

This directory defines TypeScript-style interfaces, JSDoc type contracts, and object schemas shared across the extension.

## Purpose & Scope

- Specify data contracts for internal messaging between the background service worker, popup UI, and content scripts.
- Establish strict shapes for extension state, user preferences, and internal cache entries.
- Support static type checking and IntelliSense in IDEs without adding runtime overhead.

> **Note**: Documentation only. No implementation logic is included in this architectural sprint.
