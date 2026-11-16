# syntax=docker/dockerfile:1
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SLIPWAY_ENV=production

WORKDIR /app
RUN useradd --create-home --uid 10001 slipway

# Dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY slipway ./slipway
RUN pip install .

COPY alembic.ini ./
COPY alembic ./alembic
COPY docker/entrypoint.sh /usr/local/bin/slipway-entrypoint
RUN chmod +x /usr/local/bin/slipway-entrypoint

# Stored snapshots (encrypted). docker-compose.yml mounts data/files here; Slipway runs as uid 10001.
ENV SLIPWAY_STORAGE_DIR=/var/lib/slipway
RUN mkdir -p /var/lib/slipway && chown 10001:10001 /var/lib/slipway && chmod 700 /var/lib/slipway

USER slipway
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4)" || exit 1

ENTRYPOINT ["slipway-entrypoint"]
CMD ["slipway", "serve", "--host", "0.0.0.0", "--port", "8000"]
