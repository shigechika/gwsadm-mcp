<!-- mcp-name: io.github.shigechika/gwsadm-mcp -->

# gwsadm-mcp

English | [日本語](README.ja.md)

Google Workspace **security-audit** MCP (Model Context Protocol) server —
read-only visibility into account locks, suspicious logins, and external file
sharing, built on the Admin SDK Reports API (audit activities).

Named after the admin-console viewpoint (`gwsadm` = Google Workspace admin),
sibling of [`boxadm-mcp`](https://github.com/shigechika/boxadm-mcp). This is
**not** a general-purpose Workspace MCP: it surfaces risk, it never mutates
anything.

## Features

| Tool | Description |
|------|-------------|
| `health_check` | Server version, config path, and per-domain auth probe — call at session start or after a timeout |
| `login_audit` | Reports API `login` — accounts **auto-disabled by Google** (`account_disabled_*`: leaked password, hijacked, spamming), suspicious logins, failure top-N |
| `drive_external_sharing` | Reports API `drive` — ACL **grants** to external addresses or domains (revocations reported separately) and visibility **transitions** into link/public exposure |
| `daily_brief` | One-call summary across all configured domains |
| `daily_brief_start` / `daily_brief_result` | Same as `daily_brief`, run in the background: `start` returns a `job_id` immediately, then poll `result(job_id)` until `done`. Use on large tenants where the synchronous call risks the client's ~60s tool-call timeout |

Planned: `dlp_events` (Reports `rules`; requires a Workspace edition with DLP),
`suspended_accounts` (Directory API snapshot; requires the
`admin.directory.user.readonly` DWD scope), `token_events`, `admin_events`.

## Auth model

Service account with **domain-wide delegation (DWD)** impersonating an
audit-capable admin. Fully non-interactive — no browser, no token refresh
rotation — so the server runs unattended (cron, MCP gateway, CI).

Required DWD scope per service-account client ID:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly
```

## Setup

```bash
# uv
uv pip install gwsadm-mcp

# pip
pip install gwsadm-mcp
```

Or from source:

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp

# uv
uv sync

# pip
pip install -e .
```

## Configuration

Point `GWSADM_CONFIG` at an INI file (default `~/.config/gwsadm-mcp/config.ini`,
keep it `0600`):

```ini
[gwsadm]
# optional; defaults to all [domain.*] section names
internal_domains = example.edu, mail.example.edu

[domain.example.edu]
service_account_file = /path/to/service-account.json
subject = audit-admin@example.edu
customer_id = C0xxxxxxx
```

One `[domain.*]` section per audited Workspace domain. `internal_domains` is
the allowlist used to classify sharing targets as internal vs external.

## Usage

### Claude Code

Add to `.mcp.json` (no `env` needed when the config lives at the default path;
add `"env": { "GWSADM_CONFIG": "..." }` only for a non-default location):

```json
{
  "mcpServers": {
    "gwsadm-mcp": {
      "type": "stdio",
      "command": "gwsadm-mcp"
    }
  }
}
```

### Claude Desktop

Add the same entry to `claude_desktop_config.json`.

### Direct Execution

```bash
gwsadm-mcp
```

### CLI Options

```bash
gwsadm-mcp --version   # Print version and exit
gwsadm-mcp --check     # Config + auth + API smoke for every domain, then exit
gwsadm-mcp             # Start MCP server (STDIO, default)
```

`--check` exit codes: `0` success, non-zero on config or auth failure.

## Notes

- Every result section reports `capped: true` when a window exceeded the page
  budget, or when a probe's fetch errored outright (see `event_errors`) —
  partial coverage is never presented as "no findings". The drive scan also
  reports `capped_events` (which eventNames were cut short). Narrow `hours`
  or raise `max_pages` for full coverage — on a large tenant, term-time
  weekdays can produce thousands of `change_user_access` events/day.
- Google's `visibility=shared_externally` is relative to the file **owner's**
  domain, so with multiple `internal_domains` a cross-internal-domain grant
  (e.g. student domain → staff domain) carries it too. External-ness is
  therefore judged against `internal_domains` using the grant's target:
  `target_user` for named grants, `target_domain` for domain-scoped grants
  (e.g. "anyone at partner.edu"; the literal domain `"all"` means "anyone
  with the link" and is judged by visibility instead). `risky_visibility_events`
  counts only transitions into `people_with_link` / `public_on_the_web`
  (excluding a narrowing from public down to link-only).
  `untargeted_external_transitions` is a residual bucket for transitions into
  `shared_externally` with no target address or domain to classify — it is
  not a cross-check for grants missed elsewhere, since domain-scoped grants
  are already counted above. `external_samples` / `exposure_samples` /
  `untargeted_samples` hold examples of each.
- Drive events are queried **one audit-relevant eventName at a time**, so the
  page budget is not consumed by view/edit noise; an event name rejected by the
  API degrades into `event_errors` instead of failing the tool.
  `change_document_visibility` and `change_document_access_scope` report the
  same transition as simultaneous sibling events on this API — only the
  latter drives classification (the former is fetched for its `acl_events`
  count only), so a domain-scoped grant or a link/public exposure is never
  double-counted across the two. This also means the former can no longer
  compensate if the latter's own fetch fails: a `change_document_access_scope`
  entry in `event_errors` sets `capped: true` for that domain, and its
  classification counts for the window are a lower bound even though
  `change_document_visibility` (and thus `acl_events`) may show data.
- A failure in one domain degrades only that domain's section (`{"error": ...}`).
- Read-only by design; the only API call issued is `activities().list`.
- Output contains account addresses (that is the point of an audit tool):
  restrict access to authorized security staff.

## Development

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp

# uv
uv sync --dev
uv run pytest -v
uv run ruff check .

# pip
python3 -m venv .venv
.venv/bin/pip install -e . && .venv/bin/pip install pytest ruff
.venv/bin/pytest -v
.venv/bin/ruff check .
```

## Releasing

Releases are automated with [release-please](https://github.com/googleapis/release-please).
Merging [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, …)
to `main` keeps a release PR open with the next version and changelog. Merging
that PR tags `vX.Y.Z` and publishes a GitHub Release, whose `release: published`
event triggers the `release` workflow to build and publish to PyPI and the MCP
Registry. release-please owns the version in `gwsadm_mcp/__init__.py` and
`server.json` (do not bump them by hand).

> [!IMPORTANT]
> The release-please workflow should be given a repository secret
> `RELEASE_PLEASE_TOKEN` (a PAT with `contents: write` + `pull-requests: write`).
> The default `GITHUB_TOKEN` cannot create the Release that triggers the
> downstream `release` workflow (GitHub blocks workflow runs triggered by
> `GITHUB_TOKEN`), so without the PAT nothing gets published. The workflow falls
> back to `GITHUB_TOKEN` when the secret is unset so PR CI keeps working on forks.

## License

MIT
