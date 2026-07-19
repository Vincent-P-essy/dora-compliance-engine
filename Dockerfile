# ── Stage 1: grab the static OPA binary from the official image ──────────────
FROM openpolicyagent/opa:latest-static AS opa

# ── Stage 2: application image ───────────────────────────────────────────────
FROM python:3.12-slim

# WeasyPrint needs Pango/Cairo at runtime; curl serves the healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        fonts-dejavu-core \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=opa /opa /usr/local/bin/opa

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user — the app only reads policies and talks to the DB.
RUN useradd --create-home --shell /usr/sbin/nologin dora \
    && chown -R dora:dora /app
USER dora

ENV FLASK_APP=wsgi \
    OPA_PATH=/usr/local/bin/opa \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -sf http://localhost:8000/api/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "wsgi:app"]
