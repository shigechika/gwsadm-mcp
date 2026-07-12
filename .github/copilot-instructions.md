# Repository overview

`gwsadm-mcp` is an MCP (Model Context Protocol) server exposing Google
Workspace security-audit data (login locks, suspicious logins, Drive
external-sharing exposure) to AI assistants over **stdio transport**. Built
on the official `mcp` Python SDK's `FastMCP` (`gwsadm_mcp/server.py`), with
`DomainClient` (`gwsadm_mcp/client.py`) wrapping the Admin SDK Reports API
via a service account + domain-wide delegation (DWD) credential. Read-only:
the only Admin SDK Reports API method called anywhere in this package is
`activities().list` (the underlying `googleapiclient.discovery.build()`
setup call also fetches Google's discovery document over HTTP, separately
from this read-only guarantee).

See `CLAUDE.md` for the authoritative command list and architecture notes —
read it before reviewing changes to `client.py` or `server.py`.

# Build & validate

```bash
uv sync --dev
uv run pytest -v                    # all tests
uv run ruff check .                 # lint
uv run ruff format --check .        # format check
```

This mirrors `.github/workflows/ci.yml`: a `lint` job (`ruff check` +
`ruff format --check`) and a separate `test` job (`pytest -v`) on Python
3.10/3.12/3.13 on Linux, plus one Windows 3.12 job specifically to catch
stdio newline regressions (`modelcontextprotocol/python-sdk#2433`). Both
lint and test are real CI gates here.

# What to focus review on in this repo

## 1. This is a stdio MCP server — stdout is a JSON-RPC channel, not a log

Any `print()` or library logging that writes to stdout (instead of stderr)
corrupts the protocol stream for the connected client. Currently every
`print()` in `__main__.py` lives in a branch that returns/exits before
`mcp.run()` is reached — `--version` (prints then returns) and `_check()`
(reached only via `--check`, `sys.exit(_check())`) — never concurrent with
the live `mcp.run()` server. Flag any new code path that adds a `print()`
or a logger without an explicit stderr handler that could execute while
`mcp.run()` is active.

## 2. FastMCP already wraps tool returns — don't ask for manual envelope code

`server.py`'s `@mcp.tool()`-decorated functions return plain `dict` values;
FastMCP handles the MCP content-envelope wrapping itself. Do **not** suggest
a tool handler manually construct `{"content": [...], "isError": ...}`.

## 3. Coverage contract: `capped` must be set whenever a scan is cut short

Per `server.py`'s module docstring, every result section carries a `capped`
boolean when its window was not fully scanned, so partial coverage is never
silently mistaken for "no findings" — and a failure in one domain degrades
only that domain's section (`{"error": ...}`), never the whole tool result.
`DomainClient.fetch_activities()` returns `(items, capped)` where
`capped=True` means more pages existed beyond `max_pages`. A new probe or
tool that consumes `fetch_activities` but drops the `capped` return value,
or that doesn't OR it into the enclosing section's `capped` field, breaks
this contract — flag it as a correctness bug, not a style nit.

## 4. `GwsAuthError` vs `GwsError` — the distinction is load-bearing

`GwsAuthError` (bad key file, missing DWD scope, wrong subject) means the
whole domain is unusable; a plain `GwsError` from a single probe (e.g. one
event name rejected by the API) means only that one probe failed. Since the
parallel-fetch refactor, `_parallel_fetch` catches **both** per task and
stores the exception as that task's result *value* (`results[key] = e`)
instead of raising — so seeing it catch `GwsAuthError` is correct
collection, not a bug to flag. The domain-wide-vs-per-probe distinction is
applied where each result is consumed: the aggregation loops
(`_aggregate_login`, and the per-`DRIVE_ACL_EVENTS`-name loop in
`_drive_external_sharing`) re-raise a `GwsAuthError` result via an
`isinstance` check so it propagates to the domain-level `try/except` in
`server.py` and the domain's section becomes `{"error": ...}`, while a
plain `GwsError` result is recorded in that section's `event_errors` dict
and skipped so one bad probe doesn't fail the whole domain's scan. A
consumer that drops a `GwsAuthError` result without re-raising (swallowing a
domain-wide auth failure as if it were a per-probe error), or that re-raises
a plain `GwsError` (failing the whole domain for one bad event name), is
inverting this convention — flag it.

## 5. Exception text can embed a filesystem path — check before it reaches a tool response

`client.py`'s `_reports_service()` deliberately omits the raw exception text
when a service-account key file fails to load (`# Exception text deliberately
omitted: it may embed the key path, which must not leak into tool output
visible to MCP clients`). Flag any new exception handler that includes a
caught exception's raw `str(e)` or `repr(e)` in a value returned to the MCP
client, without confirming what that exception's message can contain (file
paths, credential fragments) first — this file already has one place that
made the opposite call deliberately; a new one shouldn't do it by accident.

## 6. `is_external()`'s fail-safe default must not be relaxed

`config.py`'s `is_external()` treats an empty or malformed address as
**external** — "for a security audit, 'unknown' must not silently pass as
internal." Flag any change that makes an ambiguous or unparseable address
default to "internal" instead, in this function or in a new classification
path added elsewhere (e.g. `server.py`'s domain-scoped-grant handling).

## 7. New exposure/exclusion heuristics need the same scoping rigor as the existing ones

`server.py`'s self-creation-grant exclusion (`SELF_CREATION_GRANT_EVENTS`)
and canonical-vs-duplicate visibility-event handling
(`CANONICAL_VISIBILITY_EVENT`, `VISIBILITY_CHANGE_EVENTS`) are deliberately
scoped to specific event names, with inline comments citing observed live
API data (e.g. "live data: 361 of 363 sampled...") for why each exclusion is
safe there and must NOT be extended to other event names. A new heuristic
that broadens one of these sets, or adds a similar exclusion without an
equivalent justification (either cited data or a clear invariant), risks
silently blinding the tool's primary signal — treat it as needing the same
bar of evidence as the existing exclusions, not a green-light copy-paste.

## 8. Secrets and adversarial tool inputs

- `GWSADM_CONFIG` points at an INI file containing `service_account_file`
  paths, `subject` (impersonated admin email), and `customer_id` — flag any
  diff that logs or returns the parsed config contents, a raw API response
  containing actor emails beyond what a tool already intentionally returns,
  or credential material.
- Tool inputs (`domain`, `hours`, `max_pages`, `samples`) come from an LLM
  acting on a user's behalf — treat them as adversarial. `_select()`'s
  domain-name validation (rejects an unconfigured domain with a clear error)
  is the existing pattern for a filter parameter; a new filter parameter
  that's passed straight into an API call without validation is a gap.

## 9. Test conventions

- Tests call tool functions **directly** (`server.login_audit(...)`), not
  through a `.fn`/`_call()` wrapper — unlike some sibling MCP repos in this
  family. A new test that adds such a wrapper is inconsistent with this
  suite.
- `tests/test_server.py` injects a hand-rolled `FakeDomainClient` test
  double via the `inject` fixture (`monkeypatch.setitem(server._state,
  "clients", ...)`), not `respx` or `unittest.mock.patch` on
  `googleapiclient`. A new test that mocks HTTP directly instead of using
  `FakeDomainClient` is inconsistent with the existing suite.
- A new probe or tool needs a test covering both a normal response and a
  `capped=True` / `GwsError` / `GwsAuthError` path — see convention #3 and
  #4 above; a test suite gap on the capped/error paths is a real coverage
  gap for this codebase, not a nice-to-have.

## 10. The Reports-API fan-out is concurrent — guard its thread-safety invariants

`_parallel_fetch` runs every `(domain × eventName)` activity fetch on a
bounded `ThreadPoolExecutor` sized by `GWSADM_MAX_WORKERS` (default 8,
clamped 1..32; a non-integer value falls back to the default rather than
crashing the stdio server at startup). This is the load-bearing concurrency
surface of the codebase, so two `DomainClient` invariants keep it safe: a
double-checked `_build_lock` serializes the lazy service/credential build so
concurrent fetches build it at most once, and `_new_http()` hands out a
*fresh* `AuthorizedHttp` per call because `httplib2.Http` is not thread-safe
across `execute()`s (the googleapiclient service object may be shared, its
underlying transport may not). Flag any new `DomainClient` mutable state
added without the lock, or any new `execute()` path that shares one `Http`
across threads.

## 11. The client retries — 429/5xx and rate-limited 403s only, with full jitter

`client.py`'s `_execute` retries an `_is_retryable` error up to
`_MAX_RETRIES` (5) with full-jitter backoff. `_is_retryable` is true for
429/500/503, and for a 403 **only** when its body names a rate/quota reason
(`ratelimitexceeded` / `userratelimitexceeded` / `quotaexceeded`) — a plain
permission 403 (e.g. DWD scope not granted) is permanent and must fail
fast. Flag a "simplification" that retries all 403s (it turns a permanent
missing-scope auth failure into a backoff stall multiplied across the
parallel fan-out) or that replaces the jittered backoff with a deterministic
one (parallel fetches throttled at the same instant would then retry in
lockstep and re-collide).

# Out of scope for review comments

- `.github/workflows/release-please.yml`'s use of `secrets.RELEASE_PLEASE_TOKEN` instead of
  `GITHUB_TOKEN` is intentional (a `GITHUB_TOKEN`-authored release doesn't
  trigger the downstream `release` workflow); it falls back to
  `GITHUB_TOKEN` when the secret is unset so PR CI still passes on forks —
  don't suggest reverting it.
- `boxadm-mcp` (the sibling Box-equivalent of this server) is a separate
  repository and out of scope here.
