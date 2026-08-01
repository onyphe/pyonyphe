# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - unreleased

Full rewrite against the current ONYPHE APIv2.

### Added

- `AsyncOnyphe`, an async client mirroring the sync one.
- `pyonyphe` CLI (Typer + Rich): `user`, `search`, `export`, `summary`,
  `simple`, `resolve`, `bulk summary|simple|discovery`, `alert list|add|del`,
  `config`.
- `search_iter()` — automatic pagination up to the API's 10000-result ceiling.
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
