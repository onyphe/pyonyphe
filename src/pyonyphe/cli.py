"""``pyonyphe`` command line interface.

The command is named ``pyonyphe`` on purpose, so that it never shadows the
official Perl ``onyphe`` CLI shipped by ONYPHE.
"""

# NOTE: no `from __future__ import annotations` here -- Typer resolves the
# annotations at runtime to build the parser.

import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .client import Onyphe
from .config import load_settings
from .errors import OnypheError

app = typer.Typer(
    name="pyonyphe",
    help="Query the ONYPHE Cyber Defense Search Engine.",
    no_args_is_help=True,
    add_completion=True,
)
alert_app = typer.Typer(help="Manage ONYPHE alerts.", no_args_is_help=True)
bulk_app = typer.Typer(help="Bulk endpoints, fed from a file of assets.", no_args_is_help=True)
app.add_typer(alert_app, name="alert")
app.add_typer(bulk_app, name="bulk")

out = Console()
err = Console(stderr=True)

#: Columns shown by ``--format table``, in order, when present in a result.
TABLE_COLUMNS = (
    "@category",
    "@timestamp",
    "ip",
    "port",
    "protocol",
    "domain",
    "hostname",
    "organization",
    "country",
    "cve",
)


class State:
    """Options collected on the root command and reused by sub-commands."""

    api_key: Optional[str] = None
    base_url: Optional[str] = None
    unrated_email: Optional[str] = None
    timeout: float = 30.0


state = State()


def get_client() -> Onyphe:
    """Build a client from the global options, or exit with a clear message."""
    try:
        return Onyphe(
            state.api_key,
            base_url=state.base_url,
            unrated_email=state.unrated_email,
            timeout=state.timeout,
        )
    except OnypheError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc


def _sink(output: Optional[Path]) -> Any:
    return output.open("w", encoding="utf-8") if output else sys.stdout


def emit_ndjson(rows: Iterable[dict[str, Any]], output: Optional[Path]) -> int:
    """Write results as newline-delimited JSON. Returns the number of rows."""
    handle = _sink(output)
    count = 0
    try:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    finally:
        if output:
            handle.close()
    return count


def emit_json(payload: Any, output: Optional[Path]) -> None:
    """Write a single JSON document, pretty-printed."""
    handle = _sink(output)
    try:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    finally:
        if output:
            handle.close()


def emit_table(rows: list[dict[str, Any]], title: str = "") -> None:
    """Render results as a table, keeping only the columns that carry data."""
    if not rows:
        out.print("[yellow]no result[/yellow]")
        return
    columns = [c for c in TABLE_COLUMNS if any(c in row for row in rows)]
    if not columns:
        columns = sorted({key for row in rows for key in row})[:8]
    table = Table(title=title or None, header_style="bold")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*[_cell(row.get(column)) for column in columns])
    out.print(table)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:5])
    return str(value)


def render(rows: list[dict[str, Any]], fmt: str, output: Optional[Path], title: str = "") -> None:
    """Dispatch to the requested output format."""
    if fmt == "table":
        emit_table(rows, title)
    elif fmt == "ndjson":
        emit_ndjson(rows, output)
    else:
        emit_json(rows, output)


def run(rows: Iterator[dict[str, Any]], output: Optional[Path]) -> None:
    """Consume a streaming endpoint, reporting progress on stderr."""
    count = emit_ndjson(rows, output)
    err.print(f"[dim]{count} document(s)[/dim]")


def _version_callback(value: bool) -> None:
    if value:
        out.print(f"pyonyphe {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    api_key: Annotated[
        Optional[str],
        typer.Option("--api-key", "-k", envvar="ONYPHE_API_KEY", help="ONYPHE API key."),
    ] = None,
    base_url: Annotated[
        Optional[str], typer.Option("--base-url", envvar="ONYPHE_BASE_URL", help="API root.")
    ] = None,
    unrated_email: Annotated[
        Optional[str],
        typer.Option(
            "--unrated-email",
            envvar="ONYPHE_UNRATED_EMAIL",
            help="Login email; switches to the Unrated endpoint.",
        ),
    ] = None,
    timeout: Annotated[float, typer.Option(help="Per-request timeout, in seconds.")] = 30.0,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Global options shared by every sub-command."""
    state.api_key = api_key
    state.base_url = base_url
    state.unrated_email = unrated_email
    state.timeout = timeout


@app.command()
def config() -> None:
    """Show which endpoint and key would be used, without calling the API."""
    try:
        settings = load_settings(state.api_key, base_url=state.base_url,
                                 unrated_email=state.unrated_email)
    except OnypheError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    masked = settings.api_key[:4] + "…" + settings.api_key[-4:] if len(
        settings.api_key) > 8 else "…"
    table = Table(header_style="bold")
    table.add_column("setting")
    table.add_column("value")
    table.add_row("base_url", settings.base_url)
    table.add_row("api_key", masked)
    table.add_row("unrated", "yes" if settings.is_unrated else "no")
    out.print(table)


@app.command()
def user() -> None:
    """Show license, credits and authorisations of the current API key."""
    with get_client() as client:
        emit_json(client.user().model_dump(), None)


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="ONYPHE Query Language expression.")],
    page: Annotated[int, typer.Option(help="Page to fetch.")] = 1,
    size: Annotated[int, typer.Option(help="Results per page.")] = 100,
    all_pages: Annotated[
        bool, typer.Option("--all", help="Walk every page, up to 10000 results.")
    ] = False,
    limit: Annotated[
        Optional[int], typer.Option(help="Stop after N results (implies --all).")
    ] = None,
    trackquery: Annotated[bool, typer.Option(help="Report which sub-query matched.")] = False,
    calculated: Annotated[bool, typer.Option(help="Ask for enriched fields.")] = False,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="table, json or ndjson.")
    ] = "table",
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write to a file.")] = None,
) -> None:
    """Run an OQL search."""
    with get_client() as client:
        try:
            if all_pages or limit is not None:
                rows = list(
                    client.search_iter(
                        query,
                        size=size,
                        max_results=limit,
                        trackquery=trackquery,
                        calculated=calculated,
                    )
                )
                title = f"{len(rows)} result(s)"
            else:
                response = client.search(
                    query, page=page, size=size, trackquery=trackquery, calculated=calculated
                )
                rows = response.results
                title = f"{response.count} of {response.total} result(s)"
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    render(rows, fmt, output, title)


@app.command()
def export(
    query: Annotated[str, typer.Argument(help="ONYPHE Query Language expression.")],
    trackquery: Annotated[bool, typer.Option(help="Report which sub-query matched.")] = False,
    calculated: Annotated[bool, typer.Option(help="Ask for enriched fields.")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write to a file.")] = None,
) -> None:
    """Stream a full export as newline-delimited JSON."""
    with get_client() as client:
        try:
            run(client.export(query, trackquery=trackquery, calculated=calculated), output)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc


@app.command()
def summary(
    kind: Annotated[str, typer.Argument(help="ip, domain or hostname.")],
    value: Annotated[str, typer.Argument(help="The asset to summarise.")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="table, json or ndjson.")] = "json",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Summary API for an IP, a domain or a hostname."""
    with get_client() as client:
        try:
            response = client.summary(kind, value)  # type: ignore[arg-type]
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    render(response.results, fmt, output, f"summary {kind} {value}")


@app.command()
def simple(
    category: Annotated[str, typer.Argument(help="datascan, geoloc, vulnscan, ...")],
    value: Annotated[str, typer.Argument(help="IP, domain, hostname or string.")],
    best: Annotated[bool, typer.Option("--best", help="Best-matching document only.")] = False,
    fmt: Annotated[str, typer.Option("--format", "-f", help="table, json or ndjson.")] = "table",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Simple API (deprecated upstream, kept while it still answers)."""
    with get_client() as client:
        try:
            response = (
                client.simple_best(category, value)  # type: ignore[arg-type]
                if best
                else client.simple(category, value)  # type: ignore[arg-type]
            )
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    render(response.results, fmt, output, f"simple {category} {value}")


@app.command()
def resolve(
    value: Annotated[str, typer.Argument(help="Domain, hostname or IP address.")],
    reverse: Annotated[bool, typer.Option("--reverse", help="Reverse lookup on an IP.")] = False,
    fmt: Annotated[str, typer.Option("--format", "-f", help="table, json or ndjson.")] = "table",
) -> None:
    """Forward or reverse DNS records known to ONYPHE."""
    with get_client() as client:
        try:
            response = client.resolver_reverse(value) if reverse else client.resolver_forward(value)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    render(response.results, fmt, None, f"resolver {value}")


@bulk_app.command("summary")
def bulk_summary(
    kind: Annotated[str, typer.Argument(help="ip, domain or hostname.")],
    file: Annotated[Path, typer.Argument(help="One asset per line.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Bulk Summary API."""
    with get_client() as client:
        try:
            run(client.bulk_summary(kind, file), output)  # type: ignore[arg-type]
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc


@bulk_app.command("simple")
def bulk_simple(
    category: Annotated[str, typer.Argument(help="datascan, geoloc, vulnscan, ...")],
    file: Annotated[Path, typer.Argument(help="One IP address per line.")],
    best: Annotated[bool, typer.Option("--best", help="Best-matching document only.")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Bulk Simple API over a list of IP addresses."""
    with get_client() as client:
        try:
            rows = (
                client.bulk_simple_best(category, file)  # type: ignore[arg-type]
                if best
                else client.bulk_simple(category, file)  # type: ignore[arg-type]
            )
            run(rows, output)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc


@bulk_app.command("discovery")
def bulk_discovery(
    category: Annotated[str, typer.Argument(help="Category to query, e.g. datascan.")],
    file: Annotated[Path, typer.Argument(help="One OQL query per line.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Discovery API: several OQL queries at once (Griffin View only)."""
    with get_client() as client:
        try:
            run(client.discovery(category, file), output)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc


@alert_app.command("list")
def alert_list() -> None:
    """List the alerts configured on the account."""
    with get_client() as client:
        try:
            alerts = client.alerts()
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    if not alerts:
        out.print("[yellow]no alert[/yellow]")
        return
    table = Table(header_style="bold")
    for column in ("id", "name", "query", "email", "threshold"):
        table.add_column(column, overflow="fold")
    for alert in alerts:
        table.add_row(
            str(alert.id or ""), alert.name or "", alert.query or "",
            alert.email or "", alert.threshold or "",
        )
    out.print(table)


@alert_app.command("add")
def alert_add(
    name: Annotated[str, typer.Option(help="Alert name.")],
    query: Annotated[str, typer.Option(help="OQL query to run daily.")],
    email: Annotated[str, typer.Option(help="Where to send the alert.")],
    threshold: Annotated[str, typer.Option(help="Trigger condition on the count.")] = ">0",
) -> None:
    """Create an alert."""
    with get_client() as client:
        try:
            client.add_alert(name, query, email, threshold)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    out.print(f"[green]alert {name!r} created[/green]")


@alert_app.command("del")
def alert_del(
    alert_id: Annotated[str, typer.Argument(help="Identifier returned by 'alert list'.")],
) -> None:
    """Delete an alert."""
    with get_client() as client:
        try:
            client.del_alert(alert_id)
        except OnypheError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    out.print(f"[green]alert {alert_id} deleted[/green]")


def main() -> None:
    """Console-script entry point declared in ``pyproject.toml``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
