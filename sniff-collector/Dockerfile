FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

COPY sniff-collector/pyproject.toml sniff-collector/uv.lock sniff-collector/README.md ./
RUN uv sync --frozen --no-dev

COPY sniff-collector/main.py ./
COPY sniff-collector/sniff_collector ./sniff_collector

EXPOSE 8080

CMD ["uv", "run", "--frozen", "python", "main.py"]
