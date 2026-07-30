# Shared Constants

This directory contains cross-cutting, invariant configuration values and constants shared across the extension layers (popup, background service worker, content scripts, and API client).

## Purpose & Scope

- Maintain central definitions for API endpoints, timeout thresholds, storage keys, and event name strings.
- Prevent magic strings and hardcoded literals across different extension contexts.
- Provide a single source of truth for runtime configurations.

> **Note**: Documentation only. No implementation logic is included in this architectural sprint.
