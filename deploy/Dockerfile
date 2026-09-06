FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && curl -fsSL https://github.com/getsops/sops/releases/download/v3.9.1/sops-v3.9.1.linux.amd64 -o /usr/local/bin/sops \
    && chmod +x /usr/local/bin/sops \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY infra_agent ./infra_agent
RUN uv pip install --system ".[all]"
ENV INFRA_DATA_DIR=/app/data INFRA_SECRETS_DIR=/app/secrets INFRA_SEED_INVENTORY=/app/inventory/seed.yaml
ENTRYPOINT []
