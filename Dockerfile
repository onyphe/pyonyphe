# Build the CLI into a small runtime image.
#
# Stage 1 resolves the locked dependency set with uv; stage 2 keeps only the
# resulting virtualenv, so neither uv nor the build context ship in the final
# image.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first: this layer is cached until pyproject.toml or uv.lock move.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.13-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/sebdraven/pyonyphe" \
      org.opencontainers.image.description="CLI for the ONYPHE Cyber Defense Search Engine" \
      org.opencontainers.image.licenses="MIT"

RUN useradd --create-home --uid 1000 onyphe

COPY --from=builder --chown=onyphe:onyphe /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

USER onyphe
WORKDIR /work

ENTRYPOINT ["pyonyphe"]
CMD ["--help"]
