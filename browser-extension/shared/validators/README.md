# Shared Validators

This directory contains reusable schema validators, input sanitization routines, and payload verification helpers shared across extension components.

## Purpose & Scope

- Validate incoming backend API payloads against expected response schemas before processing.
- Verify internal runtime messages exchanged between content scripts and the service worker to prevent malformed IPC payloads.
- Provide sanitization functions for user feedback forms, URL inputs, and DOM extraction queries.

> **Note**: Documentation only. No implementation logic is included in this architectural sprint.
