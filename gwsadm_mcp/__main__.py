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


def main() -> None:
    argv = sys.argv[1:]
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
