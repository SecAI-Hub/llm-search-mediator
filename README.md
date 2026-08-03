# llm-search-mediator

[![CI](https://github.com/SecAI-Hub/llm-search-mediator/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/llm-search-mediator/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A least-privilege search bridge between an LLM client and a SearXNG instance.
It removes common PII patterns from outbound queries, adds configurable cover
traffic, bounds upstream responses, filters obvious prompt-injection patterns,
and records privacy-minimized audit events.

The filters are defense in depth. They do not make arbitrary web content safe,
provide formal differential privacy, or prevent a compromised SearXNG instance
from observing sanitized queries. Downstream models must continue to treat every
returned title, snippet, and URL as untrusted data.

## Security properties

- Egress-capable and readiness endpoints require a bearer service token and
  fail closed when it is missing or unreadable.
- An unauthenticated mode exists only behind the explicit
  `SECAI_ALLOW_INSECURE_NO_AUTH=1` switch and only on a loopback bind.
- Policy is required for search outside that development mode. Each request
  uses one no-follow, bounded snapshot validated against the strict version 1
  schema; missing, malformed, unknown, or out-of-range fields return `503`.
- SearXNG must be configured as a credential-free HTTP(S) origin. Redirects,
  ambient proxy environment variables, caller headers, and responses over
  2 MiB are rejected.
- Request bodies, queries, snippets, result counts, context, URLs, decoys, and
  batch delays are bounded. The full request-bounded query is inspected for PII
  before an overlength query is rejected.
- Audit events omit query text and query hashes. With an HMAC key, an
  authenticated checkpoint detects modification plus tail, archive, or complete
  log deletion.
- Gunicorn deliberately uses one worker because the audit tail and batch state
  are process-local; bounded threads provide concurrency.

See [the security audit](SECURITY_AUDIT.md) and
[threat model](THREAT_MODEL.md) for residual risks and production controls.

## Quick start

Use Python 3.12 or newer and the hash-locked dependencies:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
```

Create owner-only credentials and use the provided standalone policy:

```bash
umask 077
openssl rand -hex 32 | tr -d '\n' > service-token
openssl rand -hex 32 | tr -d '\n' > audit-hmac-key

SERVICE_TOKEN_PATH="$PWD/service-token" \
AUDIT_HMAC_KEY_PATH="$PWD/audit-hmac-key" \
POLICY_PATH="$PWD/examples/standalone-profile.yaml" \
AUDIT_DIR="$PWD/.local-audit" \
SEARXNG_URL="http://127.0.0.1:8888" \
BIND_ADDR="127.0.0.1:8485" \
.venv/bin/gunicorn \
  --config python:search_mediator.gunicorn_conf \
  search_mediator.app:app
```

The files must be owned by the service user or root, regular, single-link,
have no group/other permission bits (normally mode `0600` or `0400`), contain
32–4096 printable ASCII bytes, and contain no whitespace or control bytes. Use
systemd credentials or a secrets manager in production rather than
repository-local files.

Send an authenticated request:

```bash
curl --fail-with-body \
  --request POST http://127.0.0.1:8485/v1/search \
  --header "Authorization: Bearer $(tr -d '\r\n' < service-token)" \
  --header "Content-Type: application/json" \
  --data '{"query":"what is retrieval augmented generation","categories":"general"}'
```

For local experiments only, search can run without credential and policy files:

```bash
SECAI_ALLOW_INSECURE_NO_AUTH=1 \
BIND_ADDR=127.0.0.1:8485 \
AUDIT_DIR="$PWD/.local-audit" \
.venv/bin/python -m search_mediator.app
```

The application rejects that override on wildcard, LAN, or public bind
addresses.

## API

| Endpoint | Authentication | Purpose |
|---|---|---|
| `GET /live` | No | Process liveness only; does not probe SearXNG or reveal policy. |
| `GET /health` | Bearer token | Readiness, policy enablement, and SearXNG reachability. |
| `GET /v1/search/test` | Bearer token | Explicit SearXNG connectivity test. |
| `POST /v1/search` | Bearer token | Sanitized, bounded search request. |

A successful search returns sanitized result objects, a bounded context string,
the sanitized query, redaction count, decoy count, and an optional generic
uniqueness warning. Expected error statuses include `400` invalid input, `403`
bad authorization or disabled search, `413` oversized body, `422` policy block,
`502` unavailable/invalid upstream, `503` unavailable authentication or policy,
and `504` timeout.

The OpenAPI description is in [`schemas/openapi.yaml`](schemas/openapi.yaml).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8485` | Gunicorn/app listen address. Keep loopback unless a protected service network is intentional. |
| `SEARXNG_URL` | `http://127.0.0.1:8888` | Credential-free SearXNG origin; no path, query, or fragment. Use HTTPS for a remote host. |
| `POLICY_PATH` | unset | Secure YAML policy path. Required to enable search outside explicit loopback development. |
| `AUDIT_DIR` | `/var/lib/llm-search-mediator/logs` | Writable private audit directory. |
| `SERVICE_TOKEN_PATH` | unset | Preferred service-token file. |
| `SERVICE_TOKEN` | unset | Compatibility-only inline token; process environments are easier to expose. |
| `AUDIT_HMAC_KEY_PATH` | unset | Strongly recommended key file for authenticated entries and checkpoints. |
| `QUERY_DELAY_MIN` | `0.5` | Minimum random delay, clamped to finite `0..30` seconds. |
| `QUERY_DELAY_MAX` | `3.0` | Maximum random delay, clamped to finite `0..30` seconds. |
| `GUNICORN_THREADS` | `4` | Thread count, clamped to `1..16`. |
| `GUNICORN_TIMEOUT` | `60` | Worker timeout, clamped to `10..300` seconds. |

### Policy

Policy is re-read once per request so an atomic file replacement can take
effect without restart and all decisions within that request use the same
snapshot. Supported fields are intentionally small:

```yaml
version: 1
search:
  enabled: true
  allowed_categories:
    - general
  differential_privacy:
    enabled: true
    decoy_count: 2
    uniqueness_mode: warn
    batch_window: 5.0
```

`decoy_count` must be an integer in `0..10`, `batch_window` a finite number in
`0..30`, and `uniqueness_mode` one of `auto-block`, `warn`, or `allow`.
All shown keys are required and unknown keys or invalid values make policy
unavailable (`503`); they never fall back to permissive defaults. Configure
actual engines, plugins, safesearch behavior, and Tor routing in SearXNG; the
mediator does not enforce an engine allowlist.

The historical policy key name `differential_privacy` is retained for
compatibility. Decoys, generalization, uniqueness heuristics, padding, timing
jitter, and batch delay are statistical privacy measures with no epsilon/delta
guarantee. Cover traffic also increases upstream disclosure and latency.

## Audit data

Each search attempt records only:

- original query length;
- count of detected redactions;
- number of sanitized results returned;
- whether the request was blocked; and
- timestamp, event type, previous hash, entry hash, and algorithm.

Raw or sanitized query text, matched PII values, client identifiers, titles,
snippets, result URLs, and reversible low-entropy query hashes are not recorded.

The current file rotates at 50 MiB by default. Archives become mode `0400`.
When `AUDIT_HMAC_KEY_PATH` is configured, startup refuses a missing/insecure key
or an unverifiable existing chain, and an authenticated checkpoint detects tail
or full-log deletion while the checkpoint survives. Because the checkpoint is
co-located by default, deleting both the logs and checkpoint cannot be proven
locally. The implementation supports one process writer. Forward checkpoints
and archives to separately administered append-only storage for stronger
guarantees and define an external retention policy.

## Production deployment

The [`deploy/systemd/llm-search-mediator.service`](deploy/systemd/llm-search-mediator.service)
unit uses a dynamic user, systemd credentials, restrictive filesystem and
kernel settings, an empty capability set, and resource limits. Review its
network and syscall requirements on the target Fedora release before rollout.

The container uses a digest-pinned non-root Python base, applies available OS
security updates during the build, and installs hash-locked dependencies. CI
and release gates reject fixable high/critical image vulnerabilities. It binds
`0.0.0.0` inside the container but remains fail
closed until policy and token mounts are supplied. Publish ports only on an
authenticated private service network or bind the host mapping to
`127.0.0.1`. Use a read-only root filesystem, tmpfs for `/tmp`, a read-only
policy/credential mount, a writable private audit volume, dropped capabilities,
and CPU/memory/PID limits.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/ruff check search_mediator tests
.venv/bin/bandit -q -r search_mediator
.venv/bin/python -m pip_audit
.venv/bin/python -m pytest -q
```

Regenerate locks deliberately after reviewing dependency changes; CI installs
with `--require-hashes`, builds the container, and scans the final image before
release.

## SecAI_OS integration

In [SecAI_OS](https://github.com/SecAI-Hub/SecAI_OS), keep the inference runtime
without general network access and permit only authenticated calls to this
mediator. Give the mediator access only to the expected SearXNG origin, keep
SearXNG/Tor in a separate service boundary, and treat returned context as an
untrusted citation source rather than instructions.

## License

Apache-2.0. See [LICENSE](LICENSE).
