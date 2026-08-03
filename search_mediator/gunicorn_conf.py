"""Conservative Gunicorn defaults for the mediator's network boundary."""

import os

bind = os.getenv("BIND_ADDR", "127.0.0.1:8485")
# Audit-chain state is process-local, so use one worker with bounded threads.
workers = 1
threads = max(1, min(int(os.getenv("GUNICORN_THREADS", "4")), 16))
timeout = max(10, min(int(os.getenv("GUNICORN_TIMEOUT", "60")), 300))
graceful_timeout = 30
keepalive = 2
accesslog = "-"
errorlog = "-"
capture_output = True
