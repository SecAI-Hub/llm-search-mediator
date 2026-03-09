# Contributing to llm-search-mediator

## Prerequisites

| Tool | Version |
|---|---|
| Python | 3.10+ |
| pip | latest |
| git | 2.x |

## Local development

```bash
git clone https://github.com/SecAI-Hub/llm-search-mediator.git
cd llm-search-mediator
pip install -r requirements.txt
pip install pytest
python -m pytest tests/ -v
```

## Running locally

```bash
# Start SearXNG (Docker)
docker run -d -p 8888:8080 searxng/searxng

# Run the mediator
python -m search_mediator.app
```

## Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR.

## Code style

- Follow PEP 8.
- Keep functions focused and well-documented.
- Add tests for new PII patterns or injection detections.

## Pull request process

1. Fork the repo and create a feature branch.
2. Make changes with clear, focused commits.
3. Ensure all tests pass.
4. Open a PR against `main`.

## Commit message format

```
<type>: <short summary>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `security`.

## Security issues

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
