# Shared Models

This directory contains domain models and data transformation classes shared across the CyberSentinel AI browser extension.

## Purpose & Scope

- Provide domain-rich object representations for core entities such as `ThreatReport`, `ScanHistoryEntry`, `UserSession`, and `PageEvidence`.
- Encapsulate data serialization/deserialization logic, default field normalization, and immutability helpers.
- Ensure that domain entities behave consistently whether processed in the background worker or rendered in the popup UI.

> **Note**: Documentation only. No implementation logic is included in this architectural sprint.
