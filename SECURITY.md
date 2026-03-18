# Security Policy

## Supported Version

This repository currently supports the latest code on the default branch.

## Reporting a Security Issue

Please do not open a public GitHub issue for a security problem.

Instead:

1. Contact the repository owner privately.
2. Include clear reproduction steps.
3. Include the affected endpoint, input, and observed impact.
4. Mention whether the issue affects local-only usage, deployed usage, or both.

## Notes

- The app fetches remote CVE and advisory content by design.
- Security-sensitive changes should preserve request-scoped temp file cleanup.
- Internal filesystem paths should not be exposed in API responses.
