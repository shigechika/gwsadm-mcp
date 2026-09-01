# CLAUDE.md

## Overview

MCP (Model Context Protocol) server for Google Workspace security auditing.
Exposes `login_audit` (Google-side account locks, suspicious logins),
`suspended_accounts` (current suspended-account snapshot),
`get_user` (one named account's state — suspended/archived/2SV/last login —
via `users().get`, on the same `admin.directory.user.readonly` scope
`suspended_accounts` uses; a 404 answers `found: false`, never an error),
`user_oauth_tokens` (one user's third-party OAuth app grants),
`drive_external_sharing` (ACL grants to external targets, new link/public
exposure), `drive_doc_activity` (one document's owner + ACL/lifecycle
history via a server-side `doc_id` filter), `shared_drive_membership_changes`
(shared-drive member add/remove/role history), `gmail_message_trace` (did a
known Message-ID reach specific mailboxes, and where — Gmail API, requires
the separate `gmail.readonly` DWD scope, see its docstring),
`dmarc_rua_summary` (DMARC aggregate/RUA report pass/fail summary and top
reject-candidate source IPs, per domain — Gmail API against the domain's
configured `dmarc_rua_mailbox`, shares `gmail_message_trace`'s
`gmail.readonly` DWD scope but reads attachment content, not just metadata),
`group_delivery_policy` (a Google Group's own posting/delivery policy —
Groups Settings API, requires the separate `apps.groups.settings` DWD
scope), `list_group_members` (a Google Group's metadata + member roster —
Directory API, requires the separate `admin.directory.group.readonly` and
`admin.directory.group.member.readonly` DWD scopes), and a `daily_brief`
combining the Reports-based tools, to AI assistants via STDIO transport,
built on the official `mcp` Python SDK's `FastMCP`. Read-only: the only
Admin SDK / Groups Settings / Gmail API methods called anywhere in this
package are `activities().list` (Reports API), `users().list` (Directory
API, for `suspended_accounts`), `users().get` (Directory API, for
`get_user`), `tokens().list` (Directory API, for
`user_oauth_tokens`), `groups().get` / `members().list` (Directory API, for
`list_group_members`), `groups().get` (Groups Settings API, for
`group_delivery_policy`), `messages().list` / `messages().get` (Gmail
API, `format="metadata"` only, for `gmail_message_trace`), and
`messages().list` / `messages().get` (`format="full"`) /
`messages().attachments().get()` (Gmail API, for `dmarc_rua_summary` --
this one DOES read message/attachment content, not just metadata, since a
DMARC report's data lives in its attachment) — all read-only; no mutating
call exists.
The underlying `googleapiclient.discovery.build()` setup call also fetches
Google's discovery document over HTTP, separately from this guarantee.

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
  `login_audit`, `suspended_accounts`, `get_user`, `user_oauth_tokens`,
  `drive_external_sharing`, `drive_doc_activity`,
  `shared_drive_membership_changes`, `gmail_message_trace`,
  `dmarc_rua_summary`, `group_delivery_policy`, `list_group_members`, `daily_brief`,
  and the background pair `daily_brief_start` / `daily_brief_result` (plus
  an env-gated `timeout_probe` diagnostic). `gmail_message_trace` fans its
  per-recipient `DomainClient.find_message_by_id` calls across a
  `ThreadPoolExecutor` (same `_max_workers()` bound as the Reports tools)
  and resolves each recipient's `[domain.*]` client from its own address
  suffix (`_domain_of` + `_select`) unless an explicit `domain` override is
  given — so one call can cover a mixed staff/student recipient list, and
  one recipient's unresolvable domain or missing DWD scope surfaces as that
  recipient's own `error`, not a whole-call failure. Holds a module-level
  `_state` cache
  (`{"clients": ..., "internal": ...}`) built lazily on first tool call by
  `_clients()`, so `load_config()` runs once per process, not per call.
  Every audit tool fans its `(domain × eventName)` Reports-API fetches out
  through `_parallel_fetch` — or, for the single-probe doc/membership tools
  whose task shape carries a `filters` expression, the sibling
  `_fetch_drive_per_domain` — onto a bounded `ThreadPoolExecutor`
  (`GWSADM_MAX_WORKERS`, default 8, clamped 1..32) — running them serially
  would blow past a gateway's request timeout on a large tenant — then
  aggregates the collected results serially.
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
  Because `_parallel_fetch` calls `fetch_activities` from several threads at
  once, a double-checked `_build_lock` guards the lazy service build and
  `_new_http()` returns a fresh `AuthorizedHttp` per call (`httplib2.Http`
  is not thread-safe across `execute()`s). `_execute` retries an
  `_is_retryable` error — 429/500/503, and a 403 only when its body names a
  rate/quota reason (a permission 403 is permanent) — up to `_MAX_RETRIES`
  (5) with full-jitter backoff so simultaneously-throttled parallel fetches
  don't retry in lockstep.
  `DomainClient` also builds a separate Gmail API service
  (`googleapiclient.discovery.build("gmail", "v1", ...)`) per impersonated
  *user* rather than per domain — `_gmail_cache` is keyed by the recipient's
  own email address, not `self.domain`, since the DWD `subject` varies per
  call instead of being fixed like the Reports/Directory credential. Capped
  at `_GMAIL_CACHE_MAX` (500) with FIFO eviction — this cache accumulates
  one entry per distinct recipient across the process's whole lifetime, not
  per call, unlike the other three services. `message_id` is validated
  against `_MESSAGE_ID_RE` (server.py) before being interpolated into the
  `rfc822msgid:` search query, the same treatment `_DOC_ID_RE` gives
  `doc_id` in the Reports `filters` expression. The requested scope is
  `gmail.readonly`, not the narrower `gmail.metadata`: `metadata` does not
  support the `q=` search parameter `rfc822msgid:...` needs, even though the
  tool code itself only ever requests `format="metadata"` on the matched
  message.
  `get_group_settings` (Groups Settings API), `get_group`, and
  `list_group_members` (both Directory API) each build their own
  separately-credentialed service — `_groups_settings_service`,
  `_directory_group_service`, `_directory_group_member_service` — following
  the same one-scope-per-service pattern as `_directory_service` vs
  `_directory_security_service`, all impersonating the domain's fixed
  `cfg.subject` (not a per-call recipient like Gmail). Unlike
  `find_message_by_id`'s list-then-get (one scope, two calls sharing fate),
  `get_group` (`groups().get()`) and `list_group_members` (paginated
  `members().list()`, hard limit `GROUP_MEMBER_PAGE_SIZE`=200/page, distinct
  from the 500/page `users().list()` limit) are two INDEPENDENT client
  methods under two DIFFERENT DWD scopes — the `list_group_members` MCP tool
  in `server.py` calls both and degrades per-section (a scope missing on
  one side still returns the other), never letting one call's failure block
  the other from even being attempted. All three group methods
  (`get_group_settings`, `get_group`, `list_group_members`) map a plain
  HTTP 404 to `None` (via `_is_not_found`) instead of raising — verified
  live that all three underlying calls return exactly 404, never some other
  status, for a nonexistent group — so "not a group" is a normal return
  value distinguished from a real `GwsError`; `list_group_members`
  additionally only treats a 404 on the FIRST page as "not found" (a later
  page 404ing means the group was deleted mid-pagination, which stays a
  real error). The `group_delivery_policy` / `list_group_members` MCP tools
  surface this as `found: false`; this is also why their smoke probes
  (`scripts/smoke_probes.py`) can safely use a synthetic nonexistent address
  — the smoke harness treats any top-level `{"error": ...}` as an automatic
  FAIL, which a `found: false` response never triggers. `get_user`
  (`users().get`, issue #68) follows exactly that pattern for accounts rather
  than groups: 404 → `None` → `found: false`, its probe likewise a synthetic
  address. Unlike the group methods it adds NO new service — `users().get` is
  covered by `admin.directory.user.readonly` (confirmed against the Directory
  API discovery document, which lists that scope on `directory.users.get`),
  so it reuses `_directory_service()` / `_directory_creds` alongside
  `list_suspended_users`, and a tenant already running `suspended_accounts`
  needs no extra grant. Its 404 mapping rests on Google's documented
  behaviour rather than the live verification the three group calls had; the
  smoke probe is what would surface a different status. The Groups Settings API returns its
  boolean fields as the strings `"true"` / `"false"`, not JSON booleans —
  `_settings_bool()` normalizes that before it reaches tool output.
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
- `scripts/` holds the live smoke test: `smoke_test.py` (CLI), its per-tool
  specs in `smoke_probes.py`, and `smoke_harness.py` — the server-agnostic
  engine, kept identical across the servers that share it, so fix engine bugs
  once and sync the file rather than patching this copy (it is excluded from
  `ruff format` for that reason and keeps the shared copies' own style;
  `ruff check` still applies). It runs every registered tool against a real
  tenant (see README); `tests/test_smoke_probes.py` is the offline half and
  needs only the tool registry. Adding a tool without a probe spec fails CI:
  decide when you add the tool how anyone would know it works. Probes stay
  read-only, name no tenant-specific value (the account and document ids come
  from an `args_factory`), and pass an explicit small value for every bounding
  parameter a tool offers.
