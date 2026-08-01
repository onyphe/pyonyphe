# Contributing

## Setup

```bash
git clone https://github.com/sebdraven/pyonyphe
uv sync --dev
uv run pre-commit install
```

## Everyday commands

```bash
uv run ruff check .          # lint
uv run ruff check --fix .    # lint, autofixing what is safe
uv run ruff format .         # format
uv run ty check              # types
uv run zizmor .github/workflows  # audit the CI workflows
uv run pytest                # tests
uv run pytest --cov          # tests with coverage
```

CI runs exactly these, on Linux, macOS and Windows, for Python 3.10 to 3.13.

## Ruff

Ruff is both the linter and the formatter; there is no black, no isort, no
flake8. The enabled rule families live in `[tool.ruff.lint]` of
`pyproject.toml`: pycodestyle, pyflakes, isort, pep8-naming, pyupgrade,
bugbear, comprehensions, simplify, tidy-imports, use-pathlib, bandit,
annotations and the ruff-specific set. Line length is 100.

It runs in three places, and all three must agree:

- locally, via the commands above
- on commit, via the `ruff` and `ruff-format` pre-commit hooks
- in CI, as `ruff check` plus `ruff format --check`, which fails the build

If a rule genuinely does not fit, silence it narrowly with a `# noqa: RULE`
and a reason, or add it to `ignore` / `per-file-ignores` with a comment --
never disable a whole family to make one line pass.

## Workflow security

`zizmor` statically analyses `.github/workflows` for the failure modes specific
to GitHub Actions: template injection, credentials left behind by `checkout`,
over-broad `permissions`, mutable action tags. It runs locally, as a
pre-commit hook, and in the `lint` job.

Two conventions the workflows follow, both enforced by it:

- `permissions: contents: read` at the top of each file, raised per job only
  where genuinely needed (`id-token: write` for trusted publishing,
  `contents: write` to create the release).
- `persist-credentials: false` on every `checkout`, so the job token is not
  written into `.git/config` where any later step could read it.

## Design notes

- `_specs.py` describes every endpoint as a pure function returning a `Spec`.
  It performs no I/O, which is why the URL-shape tests need no network mock.
- `_base.py` holds everything the two transports share: settings, auth
  headers, request building, status-to-exception mapping, NDJSON parsing.
- `client.py` and `async_client.py` only know how to *send* a `Spec`. Adding an
  endpoint means one function in `_specs.py` and one thin method in each
  client — never two divergent implementations.

## Adding an endpoint

1. Add a spec function, with the exact path from
   <https://search.onyphe.io/docs>.
2. Add a test in `tests/test_specs.py` asserting the path and parameters.
3. Add the thin method to both clients.
4. Add a row to `docs/api.md` and, if it deserves one, a CLI command.

## Tests

`respx` mocks httpx at the transport level, so no network access is needed.
`tests/conftest.py` sandboxes `HOME` and the working directory, which keeps a
real `~/.onyphe.ini` or a local `.env` from leaking into assertions.

`tests/test_integration.py` is the exception: it calls the real API, is marked
`integration`, and is skipped unless `ONYPHE_API_KEY` is set.

```bash
uv run pytest -m 'not integration'   # what CI runs
uv run pytest -m integration         # real API, consumes credits
```

Never commit a real API key, not even in a fixture.

## Releasing

1. Update `CHANGELOG.md` and the `version` field in `pyproject.toml`.
2. Tag: `git tag vX.Y.Z && git push --tags`.
3. `release.yml` runs the tests, builds, and publishes to PyPI through trusted
   publishing (OIDC — no token stored in the repository).
