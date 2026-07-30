# Scan Response Schema Specification

This document defines the expected JSON payload structure returned by the CyberSentinel AI backend scan endpoint (`/api/v1/scan`).

## Expected Backend Response Payload

```json
{
  "url": "https://example.com/login",
  "threat_score": 85,
  "confidence": 0.96,
  "decision": "MALICIOUS",
  "recommendation": "Do not enter credentials on this site. Navigate away immediately.",
  "evidence": [
    "Suspicious form action pointing to external unauthorized domain",
    "Known phishing URL signature detected in threat intelligence database",
    "Missing SSL/TLS certificate transparency logs"
  ],
  "timestamp": "2026-07-31T00:20:00Z"
}
```

## Field Descriptions

| Field | Type | Description |
| :--- | :--- | :--- |
| `url` | `string` | The canonical target URL that was evaluated by CyberSentinel AI. |
| `threat_score` | `number` | A normalized threat rating from `0` (completely safe) to `100` (critical threat). |
| `confidence` | `number` | The AI model confidence score ranging from `0.0` to `1.0`. |
| `decision` | `string` | Classification verdict enum (`SAFE`, `SUSPICIOUS`, `MALICIOUS`). |
| `recommendation` | `string` | Clear, user-facing guidance on immediate safety actions. |
| `evidence` | `string[]` | List of human-readable forensic reasons and indicators supporting the decision. |
| `timestamp` | `string` | ISO-8601 UTC timestamp indicating when the scan was executed. |

> **Note**: This file is purely structural and API contract documentation. No scanning or backend logic is implemented.
