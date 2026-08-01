"""Deprecated compatibility shim for the 2.x import name.

``import onyphe`` keeps resolving so that existing callers do not break on the
rename, but it now points at :mod:`pyonyphe` and emits a
:class:`DeprecationWarning`. This module will be removed in 4.0.0.

**The import works; the behaviour is not identical.** 3.0 changed the return
types and collapsed most of the 2.x methods:

- non-streaming calls return a ``Response`` model, not a raw ``dict``
  (``response.results`` gets you the documents back)
- ``simple_geoloc(ip)`` and friends are now ``simple("geoloc", ip)``
- ``alert_list()`` is now ``alerts()``
- ``synscan()`` is gone -- ONYPHE dropped it

See ``docs/migration.md`` for the full mapping. Port your imports rather than
relying on this module.
"""

from __future__ import annotations

import warnings

from pyonyphe import APIError, AsyncOnyphe, Onyphe, OnypheError, ParamError

__all__ = ["APIError", "AsyncOnyphe", "Onyphe", "OnypheError", "ParamError"]

warnings.warn(
    "The 'onyphe' package was renamed to 'pyonyphe' in 3.0.0. "
    "Update your imports to 'from pyonyphe import Onyphe'; this shim will be "
    "removed in 4.0.0. Note that method signatures and return types changed "
    "as well -- see docs/migration.md.",
    DeprecationWarning,
    stacklevel=2,
)
