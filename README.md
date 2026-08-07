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
| `suspended_accounts` | Directory API — current snapshot of **suspended** accounts (`isSuspended=true`); cross-reference against a downstream IdP (e.g. KeyCloak) to find suspended-but-still-enabled accounts |
| `user_oauth_tokens` | Directory API `tokens().list` — third-party OAuth app grants for **one user**; a compromise vector `login_audit` is blind to, since a previously-granted token needs no fresh login. Domain resolved from the username's suffix, with an optional `domain` override for alias/secondary-domain addresses |
| `drive_external_sharing` | Reports API `drive` — ACL **grants** to external addresses or domains (revocations reported separately) and visibility **transitions** into link/public exposure |
| `drive_doc_activity` | Reports API `drive` with a server-side `doc_id` filter — **one document's** owner, ACL changes, and lifecycle events. Triage companion to `drive_external_sharing`: the owner (an individual vs. a shared drive's name) disambiguates the shared-drive false-positive class, where files created inside a shared drive propagate member ACLs and read as bulk external sharing |
| `shared_drive_membership_changes` | Reports API `drive` (`shared_drive_membership_change`) — who added/removed/re-roled shared-drive members and when, with external classification of the affected member and a client-side drive-name filter |
| `gmail_message_trace` | Gmail API — did a **known** Message-ID reach **specific** mailboxes, and where (inbox/spam/trash/archived)? For each recipient it impersonates that user via DWD and searches their own mailbox. Requires the separate `gmail.readonly` DWD scope (see Auth model below); a domain missing that grant reports a per-recipient error, never a false "not found" |
| `group_delivery_policy` | Groups Settings API — a Google Group's own posting/delivery policy (`who_can_post`, `allow_external_members`, moderation levels). A group's access control sits **in front of** Gmail delivery: a domain-only posting policy silently drops an external sender's mail before it generates any Gmail delivery event at all, indistinguishable from a delivery failure without reading the policy directly. Requires the separate `apps.groups.settings` DWD scope (see Auth model below) |
| `list_group_members` | Directory API — a Google Group's basic metadata and member roster, resolved directly rather than inferred from who happened to receive one particular message. Requires the separate `admin.directory.group.readonly` and `admin.directory.group.member.readonly` DWD scopes (see Auth model below) |
| `daily_brief` | One-call summary across all configured domains |
| `daily_brief_start` / `daily_brief_result` | Same as `daily_brief`, run in the background: `start` returns a `job_id` immediately, then poll `result(job_id)` until `done`. Use on large tenants where the synchronous call risks the client's ~60s tool-call timeout |

Planned: `dlp_events` (Reports `rules`; requires a Workspace edition with DLP),
`token_events`, `admin_events`.

## Auth model

Service account with **domain-wide delegation (DWD)** impersonating an
audit-capable admin. Fully non-interactive — no browser, no token refresh
rotation — so the server runs unattended (cron, MCP gateway, CI).

Grant **all** of the following DWD scopes on the same service-account client
ID up front, in one setup pass. Adding them one at a time as each tool gets
built is how a scope goes missing until the one tool that needed it starts
degrading — one place, one pass, avoids the trap:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`, `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes`, `daily_brief*` | those tools degrade to a per-domain error |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts` | that tool degrades to a per-domain error; everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | that tool degrades to a per-domain error; everything else keeps working |

`health_check` needs no scope at all to respond: it is the tool to call when
a grant might be missing — it probes each domain and reports the failing
auth in a structured per-domain result instead of failing itself.

`gmail_message_trace` needs one more scope, granted as a **separate** step —
it is intentionally not bundled into the pass above:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace` | that tool reports a per-recipient error; everything else keeps working |

This is a materially broader grant than the three above: it allows reading
*message content* for any user the service account impersonates, not just
metadata. The tool code itself only ever requests `format="metadata"` — it
never reads a message body — but the grant itself does not enforce that; the
narrower `gmail.metadata` scope was considered and rejected because it does
not support the `q=` search parameter the `rfc822msgid:` lookup needs. Grant
it on the **same** service-account client ID as the other scopes (Admin
console → Security → API controls → Domain-wide delegation → find the
existing client ID → add this scope to its list), and weigh that broader
exposure against how much you actually need message-trace before turning it
on for a given domain.

`group_delivery_policy` and `list_group_members` each need their own
separate scope too — three more grants beyond the base pass, none bundled
with each other or with `gmail.readonly` above:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/apps.groups.settings` | `group_delivery_policy` | that tool degrades to an error; everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | `list_group_members` (group metadata half) | that half reports its own error; the member roster half still works independently if its own scope below is granted |
| `https://www.googleapis.com/auth/admin.directory.group.member.readonly` | `list_group_members` (member roster half) | same, independent of the metadata half above — the two calls never gate each other |

The Groups Settings API is a distinct product from the Directory API, hence
the separate scope; it has no readonly-only variant, but this server only
ever calls `groups().get()`, never a mutating method.

`suspended_accounts` and `user_oauth_tokens` both operate per configured
domain (Directory `domain=`/`userKey=`), unlike the customer-wide Reports
tools — so every domain you want covered (e.g. a separate student domain)
needs its own `[domain.*]` config section. Note the failure modes differ:
`suspended_accounts` **silently omits** an unconfigured domain from its
result, while `user_oauth_tokens` fails loudly with an unknown-domain error.

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
- `gmail_message_trace` sets `ambiguous: true` (with `match_count`) on a
  recipient whose mailbox has more than one message under the same
  Message-ID (mailing-list copy plus a direct CC, a quarantine-release
  duplicate, …) — the rest of that recipient's fields describe only the
  first match, not a combined answer. `match_count_capped` is set alongside
  it when the mailbox has enough matches that `match_count` is a lower
  bound rather than exact (the search does not paginate).
- `group_delivery_policy` normalizes the Groups Settings API's `"true"`/`"false"`
  string fields (a quirk of that API, not JSON booleans) into real booleans in
  its output; a field absent from Google's response stays `null`, never
  coerced to `false`. `list_group_members` runs its group-metadata and
  member-roster lookups independently — a tenant with only one of the two
  DWD scopes still gets that one section, the other reported as
  `{"error": ...}` in its place. It reports `capped: true` both when the
  member roster exceeded its page budget (default 20 pages × 200/page) and
  when the member lookup failed outright (see `members_error`) — either
  way the roster is not the full one, and an empty `members` list must
  never be read as a confirmed-empty group when `capped` is true.
  Both group tools distinguish "this address is not a group" (a plain HTTP
  404, verified against production for all three underlying API calls) from
  a real failure: `group_delivery_policy` sets `found: false`;
  `list_group_members` sets it too, when either both independent lookups
  agree with no error on either side, OR one CONFIRMS not-found while the
  other independently failed (that failure is then attached as
  `group_lookup_error` / `members_lookup_error` rather than hidden) — a
  confirmed non-existence outweighs an unrelated error on the other scope.
  Only a genuine mixed state (one side not-found, the other actually
  finding data) falls through to the normal per-section shape instead.
- Read-only by design: `activities().list` (Reports API), `users().list` /
  `tokens().list` / `groups().get` / `members().list` (Directory API),
  `groups().get` (Groups Settings API), and `messages().list` / `messages().get`
  (Gmail API, metadata only) are the only API calls issued anywhere in this
  package.
- Output contains account addresses (that is the point of an audit tool):
  restrict access to authorized security staff. `gmail_message_trace` also
  returns a message snippet and headers (From/To/Cc/Subject/Date) for a
  matched message — treat its output with the same care as the mailbox
  content it is drawn from.

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

### Live smoke test

The unit suite never talks to Google, which is what makes it fast — and also
what makes it blind to a tool that has stopped returning real data.
`scripts/smoke_test.py` runs **every registered tool** against the configured
tenant and fails on empty, malformed or error answers:

```bash
# uses the same config file as the server (GWSADM_CONFIG)
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only oauth --traceback
```

- **Read-only.** Every tool here reads an audit log or a directory snapshot;
  nothing in Workspace is changed. `daily_brief_start` creates a job inside the
  process, which expires on its own.
- **No payloads in the report.** Tool names, statuses and row counts only;
  server-authored error text is redacted too, since these tools deal in account
  addresses and document titles throughout.
- **Bounded.** Every bounding parameter a tool offers is passed explicitly —
  the defaults (5 pages, 180 days, 200 events) are sized for a human asking
  once, and are enforced by a test that finds them from the source.
- **Nothing tenant-specific in the specs.** The account and the document the
  per-user and per-document tools need are discovered at run time, and skipped
  when the tenant has none to offer. Two tests keep it that way: one refuses
  those parameters as literals, the other bans anything address-shaped anywhere
  in the file, because this repository is public.
- An empty answer passes: no external sharing and no locked accounts is the
  desired state. What is asserted instead is the envelope — and, where the
  answer is keyed by domain, that the domain map is not empty, since a config
  resolving to zero domains would otherwise report every tool as working while
  auditing nothing.
- CI enforces the cheap half: a tool registered without a probe spec fails the
  build (`tests/test_smoke_probes.py`), so adding a tool forces the question
  "how would we know it works?".
- `scripts/smoke_harness.py` is the engine and holds no Workspace knowledge: it
  is kept identical across the servers that share it, so fix engine bugs once
  and sync the file rather than patching this copy.

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
