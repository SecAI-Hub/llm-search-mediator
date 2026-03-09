# llm-search-mediator

[![CI](https://github.com/SecAI-Hub/llm-search-mediator/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/llm-search-mediator/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Privacy-preserving search bridge for local LLMs.**

llm-search-mediator sits between your AI agent and the web. It sanitizes outbound queries (strips PII), pads queries to fixed sizes, sends decoy/cover searches, applies differential privacy, filters inbound results for prompt injection, and audit-logs every decision with a tamper-evident hash chain.

## Why

When LLMs search the web, two things go wrong:

1. **Privacy leakage** -- the query itself may contain PII, sensitive terms, or identifying patterns that leak through the search provider.
2. **Prompt injection** -- search results can contain adversarial text ("ignore previous instructions...") that hijacks the LLM.

llm-search-mediator solves both problems by acting as a sanitizing proxy in front of any SearXNG (or compatible metasearch) backend.

### Use cases

- Local AI assistants with web search (Claude, GPT, open-source LLMs)
- RAG pipelines that augment answers with web results
- Privacy-focused AI applications
- Any system where an LLM needs web access without leaking user data

## Features

| Feature | Description |
|---|---|
| PII stripping | Detects and redacts email, phone, SSN, credit cards, IPs, API keys, hex tokens |
| High-PII blocking | Blocks queries that are >50% redacted PII |
| Prompt injection filtering | Detects 6 injection patterns in inbound results and drops them |
| HTML sanitization | Strips tags, decodes entities, enforces snippet length limits |
| Differential privacy | Decoy queries, query generalization, k-anonymity checking |
| Traffic analysis protection | Random timing jitter, fixed-size query padding (256/512/1024 byte buckets) |
| Batch timing | Groups queries into fixed time windows to prevent timing correlation |
| Query uniqueness detection | Flags queries with proper names, addresses, case numbers |
| Hash-chained audit log | Tamper-evident JSONL audit trail with SHA-256 chain |
| Hot-reloadable policy | YAML-based policy with differential privacy settings |
| URL validation | Rejects non-HTTP(S) URLs in results |

## Quick start

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Start SearXNG

llm-search-mediator requires a running SearXNG instance. See [SearXNG docs](https://docs.searxng.org/) for setup, or use Docker:

```bash
docker run -d -p 8888:8080 searxng/searxng
```

### 3. Run

```bash
# Minimal (no policy file, search enabled by default)
python -m search_mediator.app

# With policy file
POLICY_PATH=./examples/policy.yaml python -m search_mediator.app

# With custom SearXNG URL
SEARXNG_URL=http://localhost:8888 python -m search_mediator.app
```

### 4. Search

```bash
curl -s -X POST http://127.0.0.1:8485/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"what is retrieval augmented generation"}' | jq .
```

```json
{
  "results": [
    {
      "title": "Retrieval-Augmented Generation (RAG)",
      "snippet": "RAG is a technique that combines...",
      "url": "https://example.com/rag",
      "source": "example.com"
    }
  ],
  "context": "The following information was retrieved from web search:\n[1] ...",
  "query_used": "what is retrieval augmented generation",
  "redactions": 0,
  "decoys_sent": 2
}
```

PII is automatically stripped:

```bash
curl -s -X POST http://127.0.0.1:8485/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"contact john@example.com about the project"}' | jq .query_used
```

```
"contact [EMAIL] about the project"
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check + SearXNG reachability |
| `/v1/search` | POST | Sanitized web search |
| `/v1/search/test` | GET | SearXNG connectivity test |

### POST /v1/search

**Request:**
```json
{
  "query": "how does RAG work",
  "categories": "general"
}
```

**Response (200):**
```json
{
  "results": [...],
  "context": "pre-formatted text for LLM injection",
  "query_used": "sanitized query",
  "redactions": 0,
  "decoys_sent": 2,
  "uniqueness_warning": null
}
```

**Response (422) -- query blocked:**
```json
{
  "error": "query blocked: query contains too much PII",
  "redactions": 5
}
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8485` | Listen address |
| `SEARXNG_URL` | `http://127.0.0.1:8888` | SearXNG instance URL |
| `POLICY_PATH` | (none) | Path to YAML policy file (optional) |
| `AUDIT_DIR` | `/var/lib/llm-search-mediator/logs` | Audit log directory |
| `QUERY_DELAY_MIN` | `0.5` | Minimum random delay (seconds) |
| `QUERY_DELAY_MAX` | `3.0` | Maximum random delay (seconds) |

## Policy reference

See [examples/policy.yaml](examples/policy.yaml) for a fully annotated example.

### Privacy pipeline

Every search query goes through this pipeline:

1. **PII stripping** -- 8 pattern types detected and redacted
2. **High-PII check** -- block if >50% of tokens are redacted
3. **Uniqueness check** -- flag queries with identifying patterns
4. **Query generalization** -- send a cover search for the broad category first
5. **Decoy searches** -- send N random plausible queries before the real one
6. **Batch timing** -- wait until the batch window has elapsed
7. **Random delay** -- add jitter to decorrelate timing
8. **Query padding** -- pad to fixed-size bucket (256/512/1024 bytes)
9. **SearXNG query** -- send via SearXNG (optionally through Tor)
10. **Result sanitization** -- strip HTML, check injection, validate URLs
11. **Context building** -- format results as LLM-ready context string
12. **Audit logging** -- hash-chained JSONL entry

## Hardening

For production deployment, see [deploy/](deploy/) for:
- **Systemd unit** with `DynamicUser=yes`, `PrivateNetwork=no` (needs SearXNG), `MemoryDenyWriteExecute=yes`
- **Seccomp profile** blocking dangerous syscalls

For maximum privacy, route SearXNG through Tor. See [examples/policy.yaml](examples/policy.yaml) for Tor routing setup notes.

## Integration with SecAI OS

llm-search-mediator is a core component of [SecAI OS](https://github.com/SecAI-Hub/SecAI_OS), where it runs with Tor routing, strict systemd sandboxing, and seccomp filtering.

## License

Apache-2.0. See [LICENSE](LICENSE).
