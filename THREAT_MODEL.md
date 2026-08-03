# Threat model

## Security objective

Allow a local LLM service to request bounded web-search data without granting
that inference process general egress, while reducing accidental query PII,
rejecting malformed upstream behavior, and preserving a privacy-minimized audit
trail.

The mediator is a defense-in-depth transform, not an anonymity service, content
truth oracle, prompt-injection firewall, or formal differential-privacy system.

## Trust boundaries

```text
authenticated LLM client
        |
        | raw query (untrusted)
        v
llm-search-mediator ---- private audit storage
        |
        | sanitized/padded query over a restricted route
        v
SearXNG / optional Tor ---- external engines and web pages
        |
        | results (fully untrusted)
        v
llm-search-mediator ---- sanitized result data ---- LLM client
```

| Component | Trust assumption |
|---|---|
| Client | Authenticated but its query/body is untrusted and may be malformed or contain secrets. |
| Mediator process and policy | Trusted enforcement boundary. Its image, service unit, policy, and credentials must be administrator controlled. |
| SearXNG | Trusted only to accept the configured protocol; it can observe every sanitized query and its output is fully untrusted. |
| Tor/network | Optional privacy layer; it does not hide query content from search engines and cannot defeat all timing correlation. |
| Search engines/pages | Fully untrusted and potentially malicious, poisoned, tracking, or prompt injecting. |
| Host/audit administrators | Can access metadata and control process/storage. HMAC evidence does not withstand compromise of both key and log. |

## In-scope attackers

- An unauthenticated local or network client attempting to use search egress.
- An authenticated but buggy/compromised client sending malformed or sensitive
  inputs.
- A compromised or malicious SearXNG response and malicious web content.
- A network observer correlating timing, size, destination, or topics.
- A filesystem attacker without access to the audit HMAC key attempting to
  alter or truncate logs.
- Supply-chain compromise of Python packages, container bases, or CI actions.

Root compromise, theft of both service/audit credentials, malicious
administrator policy, and flaws in the LLM itself are not fully containable by
this service.

## Threats, controls, and residual risk

### Unauthorized use as an egress proxy

`/v1/search`, `/v1/search/test`, and `/health` require an exact bearer token.
Token files are opened without following links and must be bounded,
single-link, regular, owned by root/the service user, without group/other
permission bits, at least 32 printable bytes, and free of whitespace/control bytes. Missing authentication
returns `503`; bad credentials return a generic `403`. The only no-auth path
requires an explicit development switch and a loopback bind. `/live` is
intentionally unauthenticated and reveals only process liveness.

Residual risk: a bearer token has no audience, client identity, or replay
protection. Use a protected service network and rotate it; workload identity or
mTLS is preferable for multi-tenant deployments.

### Query and metadata disclosure

The mediator removes common US-centric patterns for email, phone, SSN, payment
card, bank/routing number, passport, street address, IP, date of birth, API key,
and long hexadecimal tokens. Multiple high-risk identifiers or a query mostly
composed of redactions is blocked. Audit records omit query content, query
hashes, matched values, result content, and client metadata.

PII matching runs across the full 16 KiB request-bounded string before the
200-character outbound limit is applied. Overlength queries are rejected rather
than truncated, preventing identifiers just beyond the boundary from bypassing
inspection.

Residual risk: regexes miss semantic, novel, international, encoded, or
deliberately obfuscated identifiers. Sanitized query text, topics, timing,
language, fixed parameters, result retrieval, and destination remain observable
to SearXNG and possibly external engines. The response intentionally returns the
sanitized query to the authorized caller.

### Query correlation and fingerprinting

Optional decoys, category generalization, fixed-size padding, random delay,
bounded batch delay, and uniqueness heuristics add ambiguity. Random choices use
the operating-system-backed `secrets.SystemRandom`.

Residual risk: these mechanisms offer no epsilon/delta guarantee or measured
anonymity set. The real query can often be distinguished semantically;
whitespace padding may be normalized at later hops; decoys increase disclosure,
traffic, and latency; and an observer at both ends can correlate long-running
patterns. Do not describe this feature as formal differential privacy.

### Prompt injection and poisoned results

The service strips HTML-like tags, decodes entities, bounds strings and result
counts, rejects unsafe URL forms, and drops results matching a small set of
known injection patterns. Returned context is clearly labeled as retrieved web
content.

Residual risk: regex detection has both false positives and easy false
negatives, including Unicode obfuscation, multilingual or indirect attacks,
instructions spread across results, malicious URLs, and semantically false
content. The caller must maintain instruction/data separation, cite and verify
sources, restrict tool use, and never execute returned content.

### SSRF, redirects, and proxy redirection

SearXNG is an operator-controlled HTTP(S) origin without credentials, path,
query, or fragment. The mediator appends only fixed endpoints, disables redirect
following, ignores ambient proxy variables, sends fixed headers, and never
forwards caller headers or addresses.

Residual risk: the configured hostname can resolve differently over time and
the mediator does not enforce an IP allowlist or TLS pin. A malicious operator
configuration can target another service. Restrict egress by network policy to
the intended SearXNG address and use authenticated TLS for remote deployments.

### Resource exhaustion and malformed input

Request, query, policy, URL, result, snippet, context, decoy, delay, and
upstream-body bounds limit application work. Upstream JSON must be strict UTF-8
with an object root. Gunicorn threads/timeouts and the service/container
resource limits bound concurrency and lifetime.

All upstream calls use streaming mode. Status-only probes close immediately
after headers without consuming bodies; JSON calls decode at most 2 MiB even
when transfer encoding or compression hides the final length. A strict,
versioned policy is loaded once per request, and invalid privacy settings make
search unavailable rather than selecting a default mode.

Residual risk: requests consume a thread during intentional delays and upstream
I/O, so an authorized client can exhaust a small worker pool. JSON and HTML
processing still consume CPU inside the process. Apply upstream request-rate,
queue, connection, and per-identity quotas at a trusted proxy or client.

### Audit tampering and privacy

Audit entries form a chain; when an owner-only HMAC key is configured, entries
and an atomic checkpoint are authenticated. Startup verifies existing current
and rotated logs before append. Secure append, `fsync`, restrictive modes, and
the checkpoint detect entry changes plus archive/tail/full-log deletion.

Residual risk: the implementation is single-process and local. An attacker with
the key can forge history; deleting both the co-located checkpoint and all logs
removes the local evidence needed to prove deletion; a crash can occur between
log and checkpoint durability; and metadata can still reveal usage patterns.
Forward signed checkpoints/archives to independently administered append-only
storage and define retention/access policy.

### Supply-chain compromise

Runtime and development dependencies are hash locked and audited. The container
base uses a reviewed digest, performs no mutable OS-package transaction at build
time, and is scanned for fixable high/critical vulnerabilities. CI actions use immutable
commit SHAs, release permissions are scoped, and releases sign/attest the built
image.

Tag publication is gated on the same secret scan, static checks, tests,
dependency audits, action-pin validation, read-only container build/import, and
container vulnerability checks used for release verification. Residual risk: hashes authenticate
selected bytes, not publisher intent, and public package/container/CI
infrastructure remains trusted during deliberate updates. Review lock diffs,
scan the final image, use protected environments, and verify the emitted SBOM,
signature, and provenance at deployment.

## Deployment invariants

A production deployment must:

1. Keep inference without general egress and allow it to call only this service.
2. Require a service credential; never use the insecure development override.
3. Supply a secure, valid policy and HMAC key; fail readiness if any is absent.
4. Restrict mediator egress at the network layer to the exact SearXNG endpoint.
5. Use non-root execution, a read-only root, private writable audit storage,
   dropped capabilities, and CPU/memory/PID/open-file limits.
6. Run a single mediator process per audit stream or use an external
   concurrency-safe audit service.
7. Treat search content as untrusted data throughout the LLM/tool pipeline.
8. Monitor authentication failures, upstream failures, block rates, capacity,
   audit verification, and disk pressure without logging queries or results.
