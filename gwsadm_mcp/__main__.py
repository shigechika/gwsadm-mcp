"""Entry point: ``gwsadm-mcp`` (stdio server) / ``gwsadm-mcp --check`` / ``--version``."""

import asyncio
import os
import sys

from gwsadm_mcp import __version__


def _check() -> int:
    """Config + auth + API smoke: probes every configured domain. Exit 0 = all OK."""
    from gwsadm_mcp.client import DomainClient
    from gwsadm_mcp.config import ConfigError, config_path, load_config

    try:
        domains, internal = load_config()
    except ConfigError as e:
        print(f"Error: {e}")
        return 2
    print(f"OK: config loaded from {config_path()}")
    print(f"Domains ({len(domains)}): {', '.join(d.domain for d in domains)}")
    print(f"Internal-domain allowlist: {', '.join(sorted(internal))}")
    failed = 0
    for d in domains:
        r = DomainClient(d).check()
        if r.get("auth") == "ok":
            print(f"OK: {d.domain} — reports API reachable (DWD auth as configured subject)")
        else:
            failed += 1
            print(f"Error: {d.domain} — {r.get('detail')}")
    return 1 if failed else 0


DMARC_REPORTS_SCHEMA = "gwsadm-mcp/dmarc-reports/1"


def _dmarc_reports(argv: list[str]) -> int:
    """``gwsadm-mcp dmarc-reports``: DMARC aggregate reports that arrived in a window, as JSON."""
    import argparse
    import datetime
    import io
    import json

    from gwsadm_mcp.client import DomainClient, GwsAuthError, GwsError
    from gwsadm_mcp.config import ConfigError, load_config

    ap = argparse.ArgumentParser(
        prog="gwsadm-mcp dmarc-reports",
        description=(
            "Print every DMARC aggregate (RUA) report that ARRIVED in [--since, --until) (UTC days) "
            "as one JSON document on stdout, report by report, for archiving. Nothing is aggregated. "
            "Does not start the MCP server."
        ),
    )
    ap.add_argument("--domain", required=True, help="Configured [domain.*] section whose RUA mailbox to read.")
    ap.add_argument("--since", required=True, help="First arrival day, YYYY-MM-DD (UTC, inclusive).")
    ap.add_argument("--until", required=True, help="Last arrival day, YYYY-MM-DD (UTC, exclusive).")
    ap.add_argument("--max-pages", type=int, default=50, help="Gmail list pages of 100 messages (default 50).")
    args = ap.parse_args(argv)

    def _day(s: str) -> datetime.datetime:
        return datetime.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)

    try:
        since, until = _day(args.since), _day(args.until)
    except ValueError as e:
        print(f"dmarc-reports: bad date: {e}", file=sys.stderr)
        return 2
    if until <= since:
        print("dmarc-reports: --until must be after --since", file=sys.stderr)
        return 2
    try:
        domains, _ = load_config()
    except ConfigError as e:
        print(f"dmarc-reports: {e}", file=sys.stderr)
        return 2
    picked = [d for d in domains if d.domain == args.domain.strip().lower()]
    if not picked:
        print(f"dmarc-reports: unknown domain {args.domain!r}", file=sys.stderr)
        return 2
    try:
        got = DomainClient(picked[0]).fetch_dmarc_reports(start=since, end=until, max_pages=args.max_pages)
    except GwsAuthError as e:
        print(f"dmarc-reports: auth failed: {e}", file=sys.stderr)
        return 1
    except GwsError as e:
        print(f"dmarc-reports: failed: {e}", file=sys.stderr)
        return 1
    result = {
        "schema": DMARC_REPORTS_SCHEMA,
        "gwsadm_mcp_version": __version__,
        "domain": picked[0].domain,
        "window": {"since": since.isoformat(), "until": until.isoformat(), "basis": "arrival"},
        "fetch_complete": (
            not got["capped"]
            and got["message_errors"] == 0
            and got["non_report_attachments"] == 0
            and got["dropped_records"] == 0
        ),
        **got,
    }
    # Stream UTF-8 regardless of the console code page (Windows redirects use the ANSI one).
    sys.stdout.flush()
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
    json.dump(result, out, ensure_ascii=False)
    out.write("\n")
    out.flush()
    out.detach()
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if argv[:1] == ["dmarc-reports"]:
        sys.exit(_dmarc_reports(argv[1:]))
    if "--version" in argv:
        print(f"gwsadm-mcp {__version__}")
        return
    if "--check" in argv:
        sys.exit(_check())
    try:
        # Import lazily so --version / --check work without the MCP runtime.
        # The import sits inside the try so a ^C during the (slow) import chain
        # also exits cleanly, not just one delivered while the server runs.
        from gwsadm_mcp.server import mcp

        mcp.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        # anyio's teardown on SIGINT dumps a 20-80 line traceback. What it
        # raises out of mcp.run() is Python-version-dependent: a bare
        # KeyboardInterrupt on 3.12/3.13, but asyncio.CancelledError on 3.10
        # (asyncio.Runner.run() re-raises CancelledError instead of letting
        # KeyboardInterrupt propagate). Catch both and exit clean, same
        # convention as the sibling fleet MCP servers.
        os._exit(0)


if __name__ == "__main__":
    main()
