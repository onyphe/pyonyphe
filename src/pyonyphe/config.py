"""API key and endpoint resolution.

Resolution order, first hit wins:

1. the value passed explicitly to the client or to the CLI (``--api-key``)
2. the ``ONYPHE_API_KEY`` environment variable
3. a ``.env`` file, looked up from the current working directory upwards
4. ``$XDG_CONFIG_HOME/pyonyphe/config.toml`` (defaults to ``~/.config/pyonyphe``)
5. ``~/.onyphe.ini`` -- the file used by the official ONYPHE CLI, read for convenience

Real environment variables always win over ``.env``: the file only fills gaps.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .errors import ConfigError

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - only exercised on 3.10
    import tomli as tomllib

__all__ = ["Settings", "load_settings", "DEFAULT_BASE_URL", "UNRATED_BASE_URL"]

DEFAULT_BASE_URL = "https://www.onyphe.io/api/v2"
UNRATED_BASE_URL = "https://www.onyphe.io/unrated/api/v2"

ENV_API_KEY = "ONYPHE_API_KEY"
ENV_BASE_URL = "ONYPHE_BASE_URL"
ENV_UNRATED_EMAIL = "ONYPHE_UNRATED_EMAIL"


@dataclass(frozen=True, slots=True)
class Settings:
    """Everything needed to talk to an ONYPHE endpoint.

    :param api_key: the ONYPHE API key
    :param base_url: API root, without a trailing slash
    :param unrated_email: login email; when set, the Unrated endpoint is used
    """

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    unrated_email: str | None = None

    @property
    def is_unrated(self) -> bool:
        """Whether requests must be authenticated against the Unrated endpoint."""
        return self.unrated_email is not None


def default_config_path() -> Path:
    """Return the path of the pyonyphe TOML configuration file."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "pyonyphe" / "config.toml"


def _read_toml(path: Path) -> dict[str, str]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError:  # pragma: no cover - unreadable file
        return {}
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    section = data.get("onyphe", data)
    if not isinstance(section, dict):
        return {}
    return {str(k): str(v) for k, v in section.items() if isinstance(v, (str, int))}


def _read_ini(path: Path) -> dict[str, str]:
    """Parse the flat ``key = value`` format of ``~/.onyphe.ini``."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:  # pragma: no cover - unreadable file
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def load_settings(
    api_key: str | None = None,
    *,
    base_url: str | None = None,
    unrated_email: str | None = None,
    config_path: Path | None = None,
) -> Settings:
    """Resolve credentials from arguments, environment, then configuration files.

    :param api_key: explicit key, wins over everything else
    :param base_url: explicit API root; defaults to the Unrated root when
        ``unrated_email`` is set, to the standard root otherwise
    :param unrated_email: login email for the Unrated endpoint
    :param config_path: override the TOML configuration path (mostly for tests)
    :raises ConfigError: when no API key can be found anywhere
    """
    # Fills the environment from .env without ever overriding a real variable.
    load_dotenv(override=False)

    files: dict[str, str] = {}
    toml_path = config_path or default_config_path()
    if toml_path.is_file():
        files.update(_read_toml(toml_path))
    ini_path = Path.home() / ".onyphe.ini"
    if ini_path.is_file():
        ini = _read_ini(ini_path)
        files.setdefault("api_key", ini.get("api_key", ""))
        files.setdefault("base_url", ini.get("api_endpoint", ""))
        files.setdefault("unrated_email", ini.get("api_unrated_email", ""))

    key = api_key or os.environ.get(ENV_API_KEY) or files.get("api_key") or ""
    if not key:
        raise ConfigError(
            "No ONYPHE API key found. Pass api_key=..., set the "
            f"{ENV_API_KEY} environment variable, or write one to {toml_path}."
        )

    email = unrated_email or os.environ.get(ENV_UNRATED_EMAIL) or files.get("unrated_email") or None
    fallback = UNRATED_BASE_URL if email else DEFAULT_BASE_URL
    url = base_url or os.environ.get(ENV_BASE_URL) or files.get("base_url") or fallback

    return Settings(api_key=key, base_url=url.rstrip("/"), unrated_email=email)
