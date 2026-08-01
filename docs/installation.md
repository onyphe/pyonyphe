# Installation

## Requirements

- Python 3.11 or newer
- An ONYPHE API key — <https://www.onyphe.io/login>

## As a dependency

```bash
uv add pyonyphe
```

## From a clone

```bash
git clone https://github.com/sebdraven/pyonyphe
uv sync --dev
uv run pyonyphe --help
```

`uv sync` creates the virtualenv, resolves the lockfile and installs the
project in editable mode. There is no `pip install -r requirements.txt` step
any more: dependencies live in `pyproject.toml`, dev tools in the `dev`
dependency group.

## Configuring the API key

Resolution order, first hit wins:

1. explicit argument — `Onyphe("KEY")` or `pyonyphe --api-key KEY ...`
2. environment — `ONYPHE_API_KEY`
3. `~/.config/pyonyphe/config.toml` (or `$XDG_CONFIG_HOME/pyonyphe/config.toml`)
4. `~/.onyphe.ini` — the file the official ONYPHE CLI already uses

**`.env` is a CLI feature, not a library one.** The `pyonyphe` command loads it
at startup, searching from your working directory upwards, which places it
right after step 2. The library never touches it: importing `pyonyphe` in your
own application will not silently populate its environment. If you want that
behaviour in your code, call `dotenv.load_dotenv()` yourself.

```toml
# ~/.config/pyonyphe/config.toml
[onyphe]
api_key = "..."
# base_url = "https://www.onyphe.io/api/v2"
# unrated_email = "you@example.com"
```

Check what would be used, without spending a credit:

```bash
pyonyphe config
```

## Unrated endpoint

If your license targets the Unrated endpoint, give the client your login
email. It then authenticates with HTTP basic (`login_with_underscores:apikey`)
and repeats the key as a `k` query parameter, as ONYPHE requires.

```bash
pyonyphe --unrated-email you@example.com search 'protocol:rdp'
```

```python
Onyphe(unrated_email="you@example.com")
```
