FROM docker.io/library/python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

COPY --chown=0:0 requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY --chown=0:0 search_mediator/ search_mediator/
RUN python -m compileall -q search_mediator \
    && chown -R 0:0 /app \
    && find /app -type d -exec chmod 0555 {} + \
    && find /app -type f -exec chmod 0444 {} +

USER 65534:65534
EXPOSE 8485

ENV BIND_ADDR=0.0.0.0:8485
ENV SEARXNG_URL=http://host.docker.internal:8888
ENV AUDIT_DIR=/tmp/audit

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8485/live', timeout=2).read()"]

ENTRYPOINT ["gunicorn", "--config", "python:search_mediator.gunicorn_conf", "search_mediator.app:app"]
