# CLAUDE.md

## Overview

MCP (Model Context Protocol) server for Google Workspace security auditing.
Exposes `login_audit` (Google-side account locks, suspicious logins),
`drive_external_sharing` (ACL grants to external targets, new link/public
exposure), and a `daily_brief` combining both, to AI assistants via STDIO
transport, built on the official `mcp` Python SDK's `FastMCP`. Read-only:
the only Admin SDK Reports API method called anywhere in this package is
`activities().list` (the underlying `googleapiclient.discovery.build()`
setup call also fetches Google's discovery document over HTTP, separately
from this read-only guarantee).

## Commands

```bash
uv sync --dev
uv run pytest -v                    # run all tests
uv run ruff check .                 # lint
uv run ruff format --check .        # format check
```

This mirrors `.github/workflows/ci.yml` (separate `lint` and `test` jobs;
`test` runs on Python 3.10/3.12/3.13 on Linux plus one Windows 3.12 smoke job
to guard against stdio newline regressions).

## Architecture

- `gwsadm_mcp/server.py` — FastMCP server with `health_check`,
  `login_audit`, `drive_external_sharing`, `daily_brief`, and the background
  pair `daily_brief_start` / `daily_brief_result` (plus an env-gated
  `timeout_probe` diagnostic). Holds a module-level `_state` cache
  (`{"clients": ..., "internal": ...}`) built lazily on first tool call by
  `_clients()`, so `load_config()` runs once per process, not per call.
  `daily_brief` and the job worker share `_daily_brief_impl()`;
  `daily_brief_start` returns a `job_id` immediately and runs the work in a
  daemon thread (so a large tenant's brief never hits a client's ~60s
  tool-call timeout — issue #10, since clients don't extend it on progress
  notifications), and `daily_brief_result(job_id)` is polled until `done` /
  `error`. Jobs live in a `_JOBS` registry guarded by `_JOBS_LOCK`, bounded
  by a TTL (`_JOB_TTL_SECONDS`) reap and a hard cap (`_JOBS_MAX`).
- `gwsadm_mcp/client.py` — `DomainClient`: one instance per audited domain,
  wraps `googleapiclient.discovery.build("admin", "reports_v1", ...)` with a
  service-account + domain-wide-delegation (DWD) credential. `GwsError`
  (API/transport failure) and `GwsAuthError` (bad key, missing DWD scope,
  wrong subject) are the two exception types every caller distinguishes —
  `GwsAuthError` means the whole domain is unusable and callers re-raise it
  up to the per-domain `try/except` in `server.py`, while `GwsError` from a
  single event-name probe is caught locally and recorded per-event in
  `event_errors` so one bad probe doesn't fail the whole domain's scan.
- `gwsadm_mcp/config.py` — `load_config()` parses the `GWSADM_CONFIG` INI
  file into `list[DomainConfig]` + the `internal_domains` allowlist;
  `ConfigError` on a missing file, missing keys, or zero `[domain.*]`
  sections. `is_external()` classifies an address against that allowlist —
  empty/malformed addresses count as external (fail-safe for a security
  audit: "unknown" must never silently pass as internal).
- `gwsadm_mcp/__main__.py` — CLI entry point (`--version`/`--check`) and the
  `mcp.run()` stdio server start.

## Conventions

- Python 3.10+, `requires-python = ">=3.10"`: native `X | Y` union syntax is
  used directly in annotations.
- `ruff` lint rules: `E, F, I, W, UP`, line length 120.
- `drive_external_sharing`'s classification logic (self-creation-grant
  exclusion, canonical-vs-duplicate visibility events, untargeted
  transitions) is dense and has extensive inline comments in `server.py`
  explaining *why* each exclusion exists — read those comments before
  touching `_drive_external_sharing()`; the classification rules were
  derived from live API data (see the comments' citations of observed event
  shapes), not written speculatively.
- Tests call tool functions directly (`server.login_audit(...)`, not
  through a `.fn`/`_call()` wrapper — unlike some sibling MCP repos in this
  family). `tests/test_server.py` injects a hand-rolled `FakeDomainClient`
  test double via a `monkeypatch.setitem(server._state, ...)` fixture
  (`inject`), not `respx` or `unittest.mock.patch`.
