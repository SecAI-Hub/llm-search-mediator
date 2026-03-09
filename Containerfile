FROM docker.io/library/python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY search_mediator/ search_mediator/

USER 65534:65534
EXPOSE 8485

ENV BIND_ADDR=0.0.0.0:8485
ENV SEARXNG_URL=http://host.docker.internal:8888
ENV AUDIT_DIR=/tmp/audit

ENTRYPOINT ["python", "-m", "search_mediator.app"]
