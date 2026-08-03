# Security and production-readiness audit

Audit date: 2026-08-02
Scope: application and audit code, tests, policies/schema, dependency locks,
container, systemd service, and GitHub Actions in this repository.

This is a source-assisted engineering review, not a penetration-test
certification or a claim that search results are safe for an LLM to follow.

## Executive result

The original implementation had production-blocking authorization, privacy,
upstream, policy, audit-integrity, and supply-chain gaps. In particular, search
could run without authentication, ambient proxy variables could redirect
sensitive queries, upstream redirects/bodies were insufficiently bounded, and a
plain local hash chain could not detect tail/full-log deletion. High-confidence
remediations are implemented and covered by regression tests.

The service is suitable for further integration testing as a narrow search
boundary. Multi-tenant authentication, network-enforced SearXNG identity,
rate/queue limiting, and independently stored audit evidence remain required
before production.

## Remediated findings

| Severity | Finding | Resolution |
|---|---|---|
| Critical | Egress-capable routes were usable without authentication. | Bearer authentication is mandatory and fails closed when unavailable. A named override works only on an explicit loopback bind for development. |
| High | `HTTP_PROXY`/`HTTPS_PROXY` environment variables could reroute sanitized but sensitive searches. | The dedicated Requests session ignores ambient proxy configuration; operators configure routing in SearXNG/network policy. |
| High | SearXNG URL, redirects, caller-derived headers, and response bodies lacked a complete trust boundary. | Strict credential-free HTTP(S) origin validation, fixed endpoints/headers, no redirects, always-streamed responses, header-only status probes, bounded decompressed JSON, strict UTF-8, and object-root validation. |
| High | Policy reads could follow a link after validation, accept writable files, silently enable no-policy operation, or apply inconsistent snapshots/defaults. | No-follow descriptor reads plus one strict versioned snapshot per request; unknown, missing, wrong-type, or out-of-range fields fail search with `503`. |
| High | Audit append resumed from an unverified tail and swallowed write failures. | Startup verifies all archives/current log; append uses no-follow `O_APPEND`, mode `0600`, flush/fsync, and propagates failures. |
| High | A plain hash chain could be recomputed or lose its tail/full log without detection. | Optional HMAC-SHA256 entries and an authenticated atomic checkpoint detect modification and archive/tail/full-log deletion while the checkpoint survives; insecure configured keys fail startup. |
| High | Query truncation occurred before PII detection, allowing identifiers beyond the 200-character boundary to evade inspection. | PII scanning now covers the full request-bounded input; overlength queries are rejected after inspection instead of truncated. |
| High | Service and HMAC secrets accepted short/control-bearing values and group-readable files. | Both require 32–4096 printable bytes, no whitespace/control bytes, owner root/current service user, no group/other permission bits, and no-follow regular single-link files. |
| Medium | Audit events included a truncated low-entropy query hash and documentation claimed it was not reversible. | Query text and query hashes are no longer stored; events contain only coarse counts/length/status metadata. |
| Medium | Uniqueness matches, potentially names or addresses, were emitted in service logs. | Logs and API warnings now report only generic text/counts, never matched values. |
| Medium | Query privacy configuration accepted invalid modes/types and silently selected defaults. | OS-backed randomness plus strict complete validation; decoys must be `0..10`, delay finite `0..30`, and uniqueness mode one of the documented values or search returns `503`. |
| Medium | Request/body/category/result/URL/upstream parsing allowed malformed or oversized values. | Added 16 KiB request, 2 MiB upstream, URL/type/category checks, bounded results/context, and generic upstream errors. |
| Medium | Result URLs allowed credentials/control data and upstream results assumed expected types. | HTTP(S)-only credential-free bounded URLs, control rejection, hostname validation, and defensive object/list/string handling. |
| Medium | Multiple Gunicorn workers could fork independent audit-tail and batch state. | Production config fixes one process worker with bounded threads and documents the single-writer invariant. |
| Medium | Container/runtime dependency installs and application source permissions were mutable. | The reviewed non-root base is digest-pinned and no mutable OS-package transaction runs during the build; requirements are hash-locked, application files are root-owned/read-only, and liveness plus fixable high/critical Trivy gates are enforced. |
| Medium | Tag publication could omit checks used on ordinary CI, publish a revision outside `main`, or collapse distinct SemVer build metadata into one OCI tag. | Release verification now requires an annotated strict-SemVer tag on `main`, maps `+` to OCI-valid `_` for a collision-free immutable image tag, and runs Gitleaks, hash installs, Ruff, Bandit, pip checks/audits, tests, immutable-action validation, a read-only container build/import, and image vulnerability scanning before publish, signing, or provenance. |
| Low | Policy examples advertised engine/limit/toggle keys the service did not enforce. | Examples and documentation now expose only evaluated policy fields; security transforms remain mandatory fixed behavior. |
| Low | Rotated audit files remained broadly readable. | Archives are mode `0400`; active logs/checkpoints are mode `0600`. |
| Low | CI did not detect accidentally committed credentials. | Added an immutable-pinned Gitleaks history/worktree gate with one exact synthetic test-key allowlist. |

## Validation performed

- Python 3.12 project-local environment.
- 73 tests passing after hardening, including authentication, strict policy,
  full-input PII boundary cases, status-only and decoded upstream bounds,
  URL checks, secret-file safety, audit HMAC/tail/full deletion, and fail-closed
  startup cases.
- Ruff passing.
- Bandit passing with no reportable source findings.
- `pip-audit` reporting no known vulnerabilities in runtime and development
  hash locks.
- Container image builds successfully from the current digest-pinned base
  without mutable OS-package resolution, runs as UID/GID 65534, imports under a read-only root
  filesystem, and keeps root-owned application source mode 0444.
- Trivy reports zero fixable high/critical findings in the final image.
- GitHub Action references verified as full 40-character commit pins.
- Gitleaks history/worktree scans pass with only the exact synthetic redaction
  test value allowlisted.

## Residual risks

| Severity | Residual risk | Production control |
|---|---|---|
| High | Regex PII and prompt-injection detection have unavoidable false negatives and cannot establish semantic safety. | Keep LLM instruction/data separation, constrained tool permissions, independent source verification, and output/action approval. |
| High | SearXNG sees sanitized queries and a compromised endpoint can poison all results. DNS or operator configuration can redirect the origin. | Restrict egress to an exact private address, use authenticated TLS or a protected local socket/sidecar, isolate SearXNG, and monitor its integrity. |
| Medium | Bearer authentication is shared-secret, replayable, and has no caller identity/scope. | Use short-lived workload identity or mTLS with audience/scope and per-client authorization. |
| Medium | Authorized clients can occupy the bounded thread pool through queries, delay, decoys, and upstream timeouts. | Add trusted-proxy/per-client rate, queue, connection, and concurrency limits plus circuit breaking. |
| Medium | Statistical query privacy provides no measured anonymity guarantee and decoys create additional disclosure. | Measure against the deployment threat model, allow operators to disable cover traffic, and avoid formal differential-privacy claims. |
| Medium | Audit state is local and single-writer; compromise of both key and logs permits forgery, and deletion of both co-located logs and checkpoint cannot be proven locally. | Export signed checkpoints/archives to WORM or an independent append-only service and alert on gaps. |
| Medium | The container is only the application core; runtime security depends on invocation. | Deploy read-only, non-root, capability-free, with seccomp/AppArmor/SELinux, private volumes, no-new-privileges, and CPU/memory/PID limits. |
| Low | Strict policy is re-read on each request and has no signed distribution or readiness digest. | Distribute signed atomic policy bundles and expose only a non-sensitive policy digest/version for fleet reconciliation. |

## Comparison with SecAI_OS

The SecAI_OS deployment should own network isolation, service identity, secret
delivery, policy distribution, and monitoring. The standalone mediator should
remain a small reusable transform and use the same policy schema, audit library,
and deployment contract as the operating-system integration.

Recommended consolidation:

1. Share the hardened audit-chain implementation and a versioned policy schema.
2. Give inference an allow rule only to the authenticated mediator; give the
   mediator an allow rule only to the exact SearXNG endpoint.
3. Make readiness require policy, service credential, audit HMAC key, writable
   audit storage, and a reachable/identity-verified SearXNG endpoint.
4. Record mediator image/policy digests in SecAI_OS deployment provenance.

## Prioritized roadmap

### P0 — before production

- Add workload identity or mTLS with client-level authorization and rotation.
- Enforce egress identity by IP/network policy and authenticated TLS; add DNS
  rebinding tests and optional address pinning.
- Add front-door per-client rate/concurrency/body limits and upstream circuit
  breaking with privacy-safe metrics.
- Export HMAC checkpoints/archives to independently administered append-only
  storage and test crash/fault transitions.

### P1 — production operations

- Add Unicode normalization and configurable locale-aware PII detectors while
  preserving an operator review path for false positives.
- Replace string concatenation with a structured untrusted-content envelope for
  LLM clients and attach source-domain/digest metadata.
- Add sanitized metrics for latency, capacity, blocks, injection drops,
  upstream failures, audit state, and disk pressure.
- Produce an SBOM, scan the final image, enforce signature/provenance admission,
  and provide hardened Compose/Quadlet/Kubernetes examples.

### P2 — feature improvements

- Add optional privacy-budget/cover-traffic experiments with explicit measured
  properties instead of formal-DP terminology.
- Add pluggable, versioned inbound classifiers run in an isolated worker and
  retain deterministic regex fallbacks.
- Support multiple independently configured SearXNG pools with health-aware
  failover that never crosses an operator-defined trust domain.
- Add signed policy bundles and a dry-run policy simulator for operators.
