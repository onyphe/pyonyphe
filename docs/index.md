# Documentation

- [Installation](installation.md) — install the library and the CLI, configure the API key
- [Usage](usage.md) — sync and async clients, pagination, streaming, errors
- [CLI reference](cli.md) — every command and option
- [API reference](api.md) — method by method, with the ONYPHE endpoint behind it
- [Migrating from 2.x](migration.md) — what changed and why

## What this client talks to

Everything is the ONYPHE **APIv2**, rooted at `https://www.onyphe.io/api/v2`.
Authentication is a bearer token:

```
Authorization: bearer YOUR_APIKEY
```

The Unrated endpoint (`https://www.onyphe.io/unrated/api/v2`) is supported too;
it uses HTTP basic authentication plus a `k` query parameter, and the client
switches to it as soon as you provide a login email.

## Upstream documentation

The reference is <https://search.onyphe.io/docs>. Two chapters are worth
reading before writing any query:

- [ONYPHE Query Language](https://search.onyphe.io/docs/onyphe-query-language)
- [Historical Data Availability](https://search.onyphe.io/docs/historical-data-availability)

## Deprecations to keep in mind

ONYPHE marks the **Simple** and **Bulk Simple** APIs as deprecated and slated
for removal in APIv3. They still answer today, and this client still wraps
them, but new code should prefer Search, Export and Summary.
