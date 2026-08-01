# MCP server

`pyonyphe` ships an optional [Model Context
Protocol](https://modelcontextprotocol.io) server, so an assistant can query
ONYPHE directly.

## Install and run

```bash
uv add 'pyonyphe[mcp]'
ONYPHE_API_KEY=... pyonyphe-mcp
```

It speaks stdio, which is what desktop MCP clients expect. A typical client
configuration:

```json
{
  "mcpServers": {
    "onyphe": {
      "command": "pyonyphe-mcp",
      "env": { "ONYPHE_API_KEY": "..." }
    }
  }
}
```

The key is read from `ONYPHE_API_KEY`. Unlike the CLI, the server does not
load a `.env`: an MCP server is started by another process, in a working
directory you do not control.

## Tools

| tool | arguments | what it does |
| --- | --- | --- |
| `search` | `query`, `size=20`, `max_pages=1` | OQL search over the ONYPHE index |
| `summary` | `kind`, `value` | everything known about one IP, domain or hostname |
| `resolve` | `value`, `reverse=false` | forward or reverse DNS records |
| `user` | — | license details and remaining credits |

## What is not exposed, and why

`export` and the bulk endpoints are absent by design. They stream thousands of
NDJSON documents; feeding that into a context window is useless and expensive.
Use the CLI or the library for volume work.

## Guardrails

Each call spends real API credits, and an assistant that loops can spend a lot
of them. Three limits are enforced in the server rather than left to the
caller:

- `size` is clamped to 100, `max_pages` to 5 — at most 500 documents per call.
- Long strings are truncated at 500 characters. A single datascan document
  carries up to 16 KB in its `data` field, which would swamp everything else.
- Lists longer than 20 items are cut, with a marker giving the true count.

Errors are returned as `{"error": ..., "type": ...}` instead of being raised.
A model can reason about a `RateLimitError` or a `PaymentRequiredError` and
tell the user what happened; an exception traceback just breaks the tool call.

The `user` tool is cheap and worth calling before a broad search, to check the
remaining credits.
