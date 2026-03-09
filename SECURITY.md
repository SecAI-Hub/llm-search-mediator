# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in llm-search-mediator, please report it responsibly:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/SecAI-Hub/llm-search-mediator/security/advisories/new)

**Do not** open a public GitHub issue for security vulnerabilities.

## Disclosure timeline

| Stage | Target | Notes |
|---|---|---|
| Acknowledgement | 48 hours | Confirms receipt and assigns a tracking ID |
| Triage and severity assessment | 7 days | CVSS score assigned; reporter notified of severity |
| Fix for Critical/High | 30 days | Patch developed, reviewed, and tested |
| Fix for Medium/Low | 90 days | Addressed in next scheduled release |
| Public disclosure | After fix is released | Coordinated with reporter; CVE requested if applicable |
| Advisory publication | Same day as fix release | GitHub Security Advisory published |

## Scope

### In scope

- PII stripping bypass (patterns that leak through)
- Prompt injection filter bypass (adversarial text that passes)
- Query uniqueness detection bypass
- Audit log tampering or chain integrity bypass
- Denial of service via crafted queries
- Information leakage through timing, padding, or error messages

### Out of scope

- Vulnerabilities in Flask, requests, or PyYAML
- SearXNG or Tor vulnerabilities
- Deployment misconfigurations

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| 0.1.x (latest) | Yes | Current release; receives security fixes |
| `main` branch | Yes | Development branch; may include unreleased fixes |
| < 0.1.0 | No | No pre-release versions are supported |

Only the latest release on the `main` branch receives security updates. Users should always run the most recent tagged version.
