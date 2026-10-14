# Build the wheel with uv, then run on a clean slim base as a non-root user.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /src
COPY . .
RUN uv build --wheel --out-dir /dist

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/Nelson-PROIA/freebox-mcp" \
      org.opencontainers.image.description="Spec-driven MCP server for the Freebox OS API" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 app
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
USER app
WORKDIR /home/app
# stdio MCP only (there is no HTTP server mode). Local builds only; nothing is published.
ENTRYPOINT ["freebox-mcp"]
