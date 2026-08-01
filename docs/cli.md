# CLI reference

The command is `pyonyphe`, deliberately not `onyphe`, so it never shadows the
official Perl CLI shipped by ONYPHE.

```bash
pyonyphe --help
pyonyphe <command> --help
```

## Global options

| option | env | meaning |
| --- | --- | --- |
| `--api-key`, `-k` | `ONYPHE_API_KEY` | API key |
| `--base-url` | `ONYPHE_BASE_URL` | API root |
| `--unrated-email` | `ONYPHE_UNRATED_EMAIL` | switch to the Unrated endpoint |
| `--timeout` | | per-request timeout, seconds (default 30) |
| `--version` | | print the version and exit |

Exit codes: `0` success, `1` API or query error, `2` configuration error.

## Output formats

`--format table` (default for search-like commands) renders the columns that
carry data — `@category`, `@timestamp`, `ip`, `port`, `protocol`, `domain`,
`hostname`, `organization`, `country`, `cve`. `--format json` prints an
indented array, `--format ndjson` one document per line. `--output/-o` writes
to a file instead of stdout.

Streaming commands (`export`, `bulk *`) always write NDJSON and report the
document count on stderr, so piping stays clean:

```bash
pyonyphe export 'domain:example.com' | jq -r '.ip' | sort -u
```

## Commands

### `config`

Show the endpoint and the masked key that would be used. Calls nothing.

### `user`

License, remaining credits, authorised categories, scanned ports.

### `search QUERY`

| option | meaning |
| --- | --- |
| `--page` | page to fetch (default 1) |
| `--size` | results per page (default 100, up to 10000) |
| `--all` | walk every page, up to the 10000-result API ceiling |
| `--limit N` | stop after N results, implies `--all` |
| `--pages N` | fetch at most N pages, implies `--all` |
| `--trackquery` | report which sub-query matched |
| `--calculated` | ask for the enriched `calculated.*` fields |

```bash
pyonyphe search 'protocol:rdp country:FR' --size 20
pyonyphe search 'domain:example.com' --limit 500 --format ndjson -o hits.ndjson
pyonyphe search 'domain:example.com' --pages 5 --size 100   # 5 calls, 500 results max
```

### `export QUERY`

Streams the full result set (Eagle View and above). `--trackquery`,
`--calculated`, `--output`.

```bash
pyonyphe export 'category:vulnscan domain:example.com' -o export.ndjson
```

### `summary KIND VALUE`

`KIND` is `ip`, `domain` or `hostname`.

```bash
pyonyphe summary ip 8.8.8.8
pyonyphe summary domain example.com --format table
```

### `simple CATEGORY VALUE [--best]`

Deprecated upstream, kept while it answers. Categories: `ctl`, `datascan`,
`datashot`, `geoloc`, `inetnum`, `onionscan`, `onionshot`, `pastries`,
`resolver`, `sniffer`, `threatlist`, `topsite`, `vulnscan`, `whois`.

`--best` restricts to the best-matching document and is only available for
`geoloc`, `inetnum`, `threatlist` and `whois`.

### `resolve VALUE [--reverse]`

Forward DNS for a domain or hostname, reverse DNS for an IP with `--reverse`.

### `bulk summary KIND FILE`

One asset per line, streamed NDJSON out.

### `bulk simple CATEGORY FILE [--best]`

One IP address per line.

```bash
pyonyphe bulk simple datascan ips.txt -o datascan.ndjson
pyonyphe bulk simple whois ips.txt --best
```

### `bulk discovery CATEGORY FILE`

One OQL query per line, all run against the given category. Griffin View only.

### `alert list | add | del`

```bash
pyonyphe alert list
pyonyphe alert add --name "nginx FR" \
                   --query 'category:vulnscan domain:example.com' \
                   --email soc@example.com --threshold '>0'
pyonyphe alert del 0
```

## Shell completion

```bash
pyonyphe --install-completion
```
