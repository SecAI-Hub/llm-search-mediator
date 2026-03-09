# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-09

### Added

- Privacy-preserving search bridge for local LLMs via SearXNG
- PII stripping with 8 pattern types (email, phone, SSN, credit card, IP, DOB, API key, hex token)
- High-PII query blocking (>50% redacted)
- Prompt injection detection with 6 pattern types
- HTML sanitization for search results
- Query privacy protections: decoy queries, query generalization, k-anonymity checking
- Traffic analysis protection: random timing jitter, fixed-size query padding (256/512/1024 bytes)
- Batch timing for query decorrelation
- Query uniqueness detection (proper names, addresses, case numbers)
- Hash-chained append-only audit log with SHA-256 chain and tamper verification
- Hot-reloadable YAML policy configuration
- URL validation (reject non-HTTP(S))
- Deployment profiles: appliance (strict offline) and standalone (recommended defaults)
- Container image with Containerfile
- Systemd unit with strict sandboxing
- OpenAPI 3.0 specification
- Threat model documentation
- Privacy data retention documentation

### Security

- All queries sanitized before leaving the host
- Fail-closed on high-PII queries
- Injection detection on all inbound results
- Localhost-only SearXNG communication by default
- No raw queries or result content stored in audit log
