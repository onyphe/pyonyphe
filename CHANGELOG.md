# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.2] - 2026-08-04

### Fixed

- The Docker build failed since 3.0.1: hatch-vcs delegates to setuptools-scm,
  which reads its own `SETUPTOOLS_SCM_PRETEND_VERSION*` variables, so the
  injected version was ignored inside the build context where `.git` is
  absent. No 3.0.1 image was published as a result.

## [3.0.1] - 2026-08-04

### Fixed

- Project URLs pointed at the fork instead of `onyphe/pyonyphe`, so the PyPI
  page linked to the wrong repository. Same for the GHCR image label and the
  README badges and examples.

### Changed

- The version is now derived from the Git tag (`hatch-vcs`) instead of being
  hardcoded in `pyproject.toml`. Tagging `v3.1.0rc1` now really produces a
  `3.1.0rc1` pre-release; previously the tag name had no effect on the
  published version.

## [3.0.0] - 2026-08-04

Full rewrite against the current ONYPHE APIv2.

### Added

- `AsyncOnyphe`, an async client mirroring the sync one.
- `pyonyphe` CLI (Typer + Rich): `user`, `search`, `export`, `summary`,
  `simple`, `resolve`, `bulk summary|simple|discovery`, `alert list|add|del`,
  `config`.
- `search_iter()` — automatic pagination up to the API's 10000-result ceiling,
  bounded by `max_results` (documents) or `max_pages` (API calls).
- `/user` and Discovery endpoints, Simple Best and Bulk Simple Best.
- Typed exception hierarchy under `OnypheError`, with `RateLimitError`
  exposing `retry_after`.
- Automatic retries with exponential backoff on 429 and 5xx, honouring
  `Retry-After`.
- Configuration resolution: argument, `ONYPHE_API_KEY`,
  `~/.config/pyonyphe/config.toml`, `~/.onyphe.ini`.
- Support for the Unrated endpoint (basic auth + `k` parameter).
- `request()` escape hatch for endpoints not wrapped yet.
- `py.typed`, full type annotations, checked with `ty`.
- Ruff as the single linter and formatter, wired into pre-commit and CI.
- Support for a `.env` file (`python-dotenv`), see `.env.example`.
- CI on Linux/macOS/Windows for Python 3.10-3.13, PyPI release through
  trusted publishing.
- Container image on GHCR (`linux/amd64` and `linux/arm64`), built on every
  push to `main` and on each release.
- Optional MCP server (`pyonyphe[mcp]`, command `pyonyphe-mcp`) exposing
  `search`, `summary`, `resolve` and `user` over stdio.
- Documentation as markdown in `docs/`.

### Changed

- **Importable package renamed** `onyphe` to `pyonyphe`. `import onyphe` still
  works through a deprecation shim, removed in 4.0.0.
- Authentication moved from the `apikey` query parameter to the
  `Authorization: bearer` header.
- `requests` replaced by `httpx`.
- Non-streaming calls return a pydantic `Response` instead of a raw dict.
- The ~40 `simple_*` / `bulk_*` methods collapse into `simple(category, ...)`,
  `simple_best(...)`, `bulk_simple(...)`, `bulk_summary(...)`. See
  `docs/migration.md`.
- `alert_list()` is now `alerts()` and returns `list[Alert]`.
- `add_alert()` takes a `threshold` argument.
- Packaging moved from `setup.py` + `requirements.txt` to `pyproject.toml`
  with hatchling, a `src/` layout, and uv for dependency management.
- Minimum Python is now 3.10.

### Fixed

- `search()` and `export()` sent the OQL query in the URL path; the API
  expects it in the `q` query parameter.
- Bulk endpoint typos: `bulk/simple/clt/ip` and `bulk/simple/inetenum/ip`
  never resolved.
- Bare `except:` clauses swallowed everything, including `KeyboardInterrupt`.
- Bulk methods leaked an open file handle per call.
- Bulk payloads are normalised to LF endings: an asset list written on Windows
  used to send carriage returns as part of each value.

### Removed

- `synscan()` and `simple_synscan()`: ONYPHE dropped synscan from the Simple
  API. Use `search("category:synscan ...")`.
- The Sphinx documentation build.

## [2.0] - 2021

- APIv2 support.
