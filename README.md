<!-- mcp-name: io.github.shigechika/gwsadm-mcp -->

# gwsadm-mcp

English | [日本語](README.ja.md)

Google Workspace **security-audit** MCP (Model Context Protocol) server —
read-only visibility into account locks, suspicious logins, and external file
sharing, built on the Admin SDK Reports API (audit activities).

Named after the admin-console viewpoint (`gwsadm` = Google Workspace admin),
sibling of [`boxadm-mcp`](https://github.com/shigechika/boxadm-mcp). This is
**not** a general-purpose Workspace MCP: it surfaces risk and changes nothing,
with one opt-in exception — `sign_out_user`, which exists only when the server
is started with `GWSADM_ENABLE_SIGN_OUT=1`.

## Features

| Tool | Description |
|------|-------------|
| `health_check` | Server version, config path, and per-domain auth probe — call at session start or after a timeout |
| `login_audit` | Reports API `login` — accounts **auto-disabled by Google** (`account_disabled_*`: leaked password, hijacked, spamming), suspicious logins, failure top-N |
| `gmail_usage_report` | Reports API `customerUsageReports` — daily Gmail send/receive counts per domain, one date at a time, ending yesterday (the API's own UTC-8:00/PST date anchor). Requires the separate `admin.reports.usage.readonly` DWD scope (see Auth model below) — a DIFFERENT grant from `admin.reports.audit.readonly` even though both are Reports API |
| `suspended_accounts` | Directory API — current snapshot of **suspended** accounts (`isSuspended=true`); cross-reference against a downstream IdP (e.g. KeyCloak) to find suspended-but-still-enabled accounts |
| `get_user` | Directory API `users().get` — **one named account's** current state: `suspended` (with reason and time), `archived`, `last_login`, 2SV enrolled/enforced, org unit, creation time, pending password change. The "why can't this person sign in" lookup: one request, no pagination, for an address you already know — unlike `suspended_accounts`, which lists only accounts that ARE suspended, so it can never confirm that a given address is *not* suspended (and once that list exceeds its page cap, absence stops being evidence either way). Needs no scope beyond the one `suspended_accounts` already uses |
| `user_oauth_tokens` | Directory API `tokens().list` — third-party OAuth app grants for **one user**; a compromise vector `login_audit` is blind to, since a previously-granted token needs no fresh login. Domain resolved from the username's suffix, with an optional `domain` override for alias/secondary-domain addresses |
| `sign_out_user` | **State-changing, opt-in.** Directory API `users().signOut` — signs **one** account out of every web and device session and resets its sign-in cookies, after confirming the account exists with `users().get`. Registered only when the server starts with `GWSADM_ENABLE_SIGN_OUT=1`; put an approval step in front of it. Does not revoke OAuth grants or app passwords, remove an enrolled second factor or change the password (listed in its `not_covered`). Needs two grants: `admin.directory.user.readonly` for the account check (as `get_user`) and `admin.directory.user.security` for the sign-out itself (as `user_oauth_tokens`); the impersonated admin must also be allowed to manage user security. Answers `signed_out` `true` (Google confirmed), `false` (nothing changed) or `null` (outcome unknown: sent, no answer in time) with the same keys every time, and ends within `GWSADM_SIGN_OUT_DEADLINE_SECONDS` (default 45). The address's own domain must be configured; `domain`, if given, must match it. |
| `user_activity` | Reports API `activities().list` with `userKey=<username>` — everything **one account** did in a window, merged across applications (login, token, user_accounts, drive, groups, calendar, chat, meet, saml by default) newest first. `flags` surfaces the events that change the account's security posture regardless of volume — 2SV enrolled/disabled, recovery email/phone changed, password changed, outbound forwarding, Google's `risky_sensitive_action_*` / `suspicious_login` verdicts, every OAuth `authorize` with client and scopes — because a second factor the attacker enrolled survives a password reset; `ips` lists the distinct source addresses with first/last seen. Google's own `account_disabled_*` / `suspicious_login` verdicts are not served under the account's `userKey` (their actor is Google), so they are fetched the way `login_audit` does and reported under the synthetic application `login_verdicts`. The post-compromise question `login_audit` cannot answer: it sees only the events Google itself raised, domain-wide |
| `ip_activity` | Reports API `activities().list` with `actorIpAddress=<ip>` — every account **one source address** acted as, per domain and application, with the same `flags`. The follow-through after `user_activity` names an attacker's address: did the same source reach other accounts? A spray shows up as `login_failure` counts before it ever succeeds |
| `compromise_sweep` | The Google-side follow-through after **one account** is confirmed compromised, in one call: `activity` (`user_activity`, flags first), `state` / `grants` (`get_user`; OAuth grants with mail / Drive / contacts / admin scopes called out as `risky`), `ips` (`ip_activity` across every domain for the attacker's addresses — given, or taken from the account's own flags — with the account itself excluded), and `gmail`: the settings an attacker leaves behind to keep reading mail (auto-forwarding, forwarding addresses, filters that forward / delete / archive, delegates, send-as and reply-to) plus what the mailbox sent in the window as counts and recipient domains — never a subject or body. `gmail.kind` says whether it could be read at all: `ok` / `partial` (one settings section or the sent summary failed; the rest stands) / `api_disabled` (the Gmail API is off in the service account's own Cloud project) / `no_grant` / `error` — a failure is reported, never read as "nothing found". `highlights` lists the facts to act on, `checklist` what remains to do by hand. Shares `gmail_message_trace`'s `gmail.readonly` DWD scope (every settings read, `delegates.list` included, is served by it — verified live) |
| `drive_external_sharing` | Reports API `drive` — ACL **grants** to external addresses or domains (revocations reported separately) and visibility **transitions** into link/public exposure |
| `drive_doc_activity` | Reports API `drive` with a server-side `doc_id` filter — **one document's** owner, ACL changes, and lifecycle events. Triage companion to `drive_external_sharing`: the owner (an individual vs. a shared drive's name) disambiguates the shared-drive false-positive class, where files created inside a shared drive propagate member ACLs and read as bulk external sharing |
| `shared_drive_membership_changes` | Reports API `drive` (`shared_drive_membership_change`) — who added/removed/re-roled shared-drive members and when, with external classification of the affected member and a client-side drive-name filter |
| `admin_actions` | Reports API `admin` — what administrators (people, or a sync or API client acting as one) did in the Admin console: to **one user or group** (server-side `USER_EMAIL` / `GROUP_EMAIL` filters on the target's domain) or tenant-wide. Answers "who suspended this account / reset its password / took it out of a group?", which `user_activity` cannot: an admin event's actor is the administrator, not the account acted upon |
| `workspace_status` | Google Workspace Status Dashboard (public feed, no credential) — open incidents and those that ended within the window, optionally for one product (`Gmail`, `Drive`, ...). Answers "is it Google?" before a tenant-side investigation |
| `gmail_message_trace` | Gmail API — did a **known** Message-ID reach **specific** mailboxes, and where (inbox/spam/trash/archived)? For each recipient it impersonates that user via DWD and searches their own mailbox. Requires the separate `gmail.readonly` DWD scope (see Auth model below); a domain missing that grant reports a per-recipient error, never a false "not found" |
| `dmarc_rua_summary` | Gmail API — DMARC aggregate (RUA) report pass/fail summary and top reject-candidate source IPs, per domain. Impersonates the domain's configured `dmarc_rua_mailbox` (a real user; default `postmaster@<domain>`), searches it for mail addressed to `dmarc_rua_recipient` (the published `rua=` address, e.g. `postmaster+rua@`; default: the mailbox) and reads the compressed report attachments those messages carry. Shares `gmail_message_trace`'s `gmail.readonly` DWD scope, but unlike that tool this one DOES read attachment content (the report XML), not just metadata — see Auth model below |
| `group_delivery_policy` | Groups Settings API — a Google Group's own posting/delivery policy (`who_can_post`, `allow_external_members`, moderation levels). A group's access control sits **in front of** Gmail delivery: a domain-only posting policy silently drops an external sender's mail before it generates any Gmail delivery event at all, indistinguishable from a delivery failure without reading the policy directly. Requires the separate `apps.groups.settings` DWD scope (see Auth model below) |
| `list_group_members` | Directory API — a Google Group's basic metadata and member roster, resolved directly rather than inferred from who happened to receive one particular message. Requires the separate `admin.directory.group.readonly` and `admin.directory.group.member.readonly` DWD scopes (see Auth model below) |
| `daily_brief` | One-call summary across all configured domains, including account-protection changes (2-Step Verification, passkeys, Advanced Protection, password, recovery address/phone, mail forwarding out of the domain) flagged when they come from outside your home countries (`GWSADM_IP2ASN`, `GWSADM_HOME_COUNTRIES`), from an origin that cannot be placed, or follow a suspicious login |
| `daily_brief_start` / `daily_brief_result` | Same as `daily_brief`, run in the background: `start` returns a `job_id` immediately, then poll `result(job_id)` until `done`. Use on large tenants where the synchronous call risks the client's ~60s tool-call timeout |

Planned: `dlp_events` (Reports `rules`; requires a Workspace edition with DLP),
`token_events`.

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
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`, `user_activity`, `ip_activity`, `admin_actions`, `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes`, `daily_brief*` | those tools degrade to a per-domain error |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`, `get_user`, `sign_out_user` (opt-in; its account check) | those tools degrade to an error (per-domain for `suspended_accounts`); everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens`, `sign_out_user` (opt-in) | those tools degrade to a per-domain error; everything else keeps working |

`health_check` needs no scope at all to respond: it is the tool to call when
a grant might be missing — it probes each domain and reports the failing
auth in a structured per-domain result instead of failing itself.

`gmail_usage_report` needs its own separate scope too, despite living under
the same Admin SDK Reports API as the base pass above — the "Usage report"
family (`customerUsageReports`) and the "Audit" activity stream
(`activities().list`, everything else in the base pass) are gated by two
different scopes, and having one does not imply the other:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/admin.reports.usage.readonly` | `gmail_usage_report` | that tool degrades to a per-domain error; everything else keeps working |

`gmail_message_trace` and `dmarc_rua_summary` need one more scope, granted as
a **separate** step — it is intentionally not bundled into the pass above:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace`, `dmarc_rua_summary`, `compromise_sweep` (its `gmail` section) | those tools report a per-recipient/per-domain error; everything else keeps working |

This is a materially broader grant than the three above: it allows reading
*message content* for any user the service account impersonates, not just
metadata. `gmail_message_trace` only ever requests `format="metadata"` — it
never reads a message body — but `dmarc_rua_summary` DOES read content: it
fetches the compressed DMARC report attachment each RUA message carries
(`format="full"` plus `attachments().get()`) and parses it. Both stay within
what the grant allows either way, but only `gmail_message_trace` stays inside
the narrower "metadata only" habit; the narrower `gmail.metadata` scope was
considered and rejected for both tools because it does not support the `q=`
search parameter the `rfc822msgid:`/RUA-mailbox lookups need. Grant it on the
**same** service-account client ID as the other scopes (Admin console →
Security → API controls → Domain-wide delegation → find the existing client
ID → add this scope to its list), and weigh that broader exposure against how
much you actually need message-trace/DMARC reporting before turning it on for
a given domain.

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

`suspended_accounts`, `get_user` and `user_oauth_tokens` all operate per
configured domain (Directory `domain=`/`userKey=`), unlike the customer-wide
Reports tools — so every domain you want covered (e.g. a separate student
domain) needs its own `[domain.*]` config section. Note the failure modes
differ: `suspended_accounts` **silently omits** an unconfigured domain from
its result, while `get_user` and `user_oauth_tokens` fail loudly with an
unknown-domain error (both take a `domain` override for an alias/secondary
address whose suffix has no section of its own).

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
dmarc_rua_mailbox = postmaster@example.edu   # optional, default: postmaster@<domain>; "none" opts out
dmarc_rua_recipient = postmaster+rua@example.edu   # optional, default: same as dmarc_rua_mailbox
```

One `[domain.*]` section per audited Workspace domain. `internal_domains` is
the allowlist used to classify sharing targets as internal vs external.
`dmarc_rua_mailbox` is the real user `dmarc_rua_summary` impersonates to read
DMARC aggregate reports — domain-wide delegation can only act as an actual user,
never as a group or alias. `dmarc_rua_recipient` is the address the reports are
sent to (the `rua=mailto:` value published in the domain's `_dmarc` record) and
is used only to narrow the Gmail search (`to:<recipient>`); it defaults to the
mailbox. Set it when the published address is a Gmail plus-subaddress such as
`postmaster+rua@` (searching on it also keeps `ruf=` failure reports sent to
`postmaster+ruf@` out of the aggregate parse) or a group that fans out to the
impersonated inbox. `dmarc_rua_mailbox = none` opts a domain out of DMARC reading
— e.g. when its `rua=` points at another domain's mailbox that a different
`[domain.*]` section already reads; reports are grouped by the policy domain each
report names, so they still appear under that other section.

Environment variables (all optional except where noted):

| Variable | Default | Meaning |
|---|---|---|
| `GWSADM_CONFIG` | `~/.config/gwsadm-mcp/config.ini` | the INI file above |
| `GWSADM_MAX_WORKERS` | `8` | concurrent Reports API fetches in the fan-out (clamped to 1–32; a non-integer falls back to 8). Lower it if a tenant throttles, raise it if a large tenant's scan is too slow |
| `GWSADM_SITES_INI` | — | your own address ranges, to name where an account-protection change came from (see the setup docs) |
| `GWSADM_IP2ASN` / `GWSADM_HOME_COUNTRIES` | — | iptoasn table and home countries, to flag changes from abroad (see the setup docs) |
| `GWSADM_ENABLE_SIGN_OUT` | unset | `1` registers the state-changing `sign_out_user` |
| `GWSADM_SIGN_OUT_DEADLINE_SECONDS` | `45` | time budget of one `sign_out_user` call (clamped to 10–300) |

## Usage

### Claude Code (plugin)

This repository doubles as a single-plugin marketplace, so Claude Code can
install the server for you:

```
/plugin marketplace add shigechika/gwsadm-mcp
/plugin install gwsadm-mcp@gwsadm-mcp
```

The plugin launches `uvx gwsadm-mcp` and reads `GWSADM_CONFIG` (falls back to
`~/.config/gwsadm-mcp/config.ini`), the same variable described in
[Configuration](#configuration). `/plugin install` only wires up the server
process — it cannot create the config INI or the Google Cloud service-account
JSON key(s) it points at; both must already exist on the machine running the
plugin before any tool call will succeed.

`uvx` must be on the `PATH` of the process that runs Claude Code — a login
shell usually has it, but a GUI-launched app may not; install
[uv](https://docs.astral.sh/uv/) system-wide if the plugin fails to start.

### Claude Code (manual)

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

### Codex

```bash
codex mcp add gwsadm-mcp -- gwsadm-mcp
```

Add `--env GWSADM_CONFIG=...` (before `--`) only if the config INI is not at
the default path (`~/.config/gwsadm-mcp/config.ini`).

### Gemini CLI

Add to `~/.gemini/settings.json` (or a project's `.gemini/settings.json`):

```json
{
  "mcpServers": {
    "gwsadm-mcp": {
      "command": "gwsadm-mcp"
    }
  }
}
```

As with Codex, add `"env": { "GWSADM_CONFIG": "..." }` only for a non-default
config location. To expose only some tools, list them in `includeTools`.

Any other MCP client that launches stdio servers works the same way: give it
`gwsadm-mcp` as the command.

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

### Archiving DMARC reports (batch)

`dmarc_rua_summary` aggregates a rolling window for a patrol. To keep a day-by-day history, a scheduled job can dump the reports themselves:

```bash
gwsadm-mcp dmarc-reports --domain example.edu --since 2026-09-20 --until 2026-09-23 > reports.json
```

- Reads the same RUA mailbox as `dmarc_rua_summary` (same `gmail.readonly` scope) for messages that **arrived** in `[--since, --until)` (UTC days, Gmail `after:` / `before:`), every attachment and every ZIP entry (up to 20 entries and 50 MB decompressed per attachment; anything past that, or an encrypted / corrupt entry, is counted in `non_report_attachments`).
- Prints one JSON document to stdout: each report whole — `org_name`, `report_id`, `begin` / `end` (epoch seconds of the reported period), the published `policy` (`p`, `sp`, `pct`, `adkim`, `aspf`) and its records with `reason` and `auth_results`. Nothing is aggregated or deduplicated: some reporters split one report across several messages under the same `report_id`, so deduplicate on content, not on the id.
- `fetch_complete` is true only when nothing was capped and no message, attachment or record was skipped (`message_errors`, `non_report_attachments`, `dropped_records`).
- Exit `2` for a bad argument or configuration, `1` for an API or auth failure (e.g. the scope was revoked); nothing is written to stdout in either case.
- The output contains sender IPs and header domains. Keep it out of anything published.

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
- `get_user` distinguishes "this address names no account" from "the lookup
  failed": a plain HTTP 404 answers `found: false` with no state fields,
  which is a diagnostic result — a typo'd or deleted address — and never an
  `error`. A missing DWD scope or a transient failure answers `{"error": ...}`
  with no `found` key instead, so the two can never be confused in either
  direction. Fields Google omits stay `null` rather than being coerced:
  a missing `suspended` must not read as "the account is fine".
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
- Read-only by design, with one opt-in exception. The only read calls issued are
  `activities().list()` and `customerUsageReports().get()` (Reports API);
  `users().list()`, `users().get()`, `tokens().list()`, `groups().get()`,
  `members().list()` (Directory API); `groups().get()` (Groups Settings API); and
  in the Gmail API `messages().list()` / `messages().get(format="metadata")` for
  `gmail_message_trace` and `compromise_sweep` (the latter with the
  To/Cc/Bcc/Date headers only), `messages().list()` /
  `messages().get(format="full")` / `messages().attachments().get()` for
  `dmarc_rua_summary` (which does read the report attachments, not just
  metadata), the settings reads `users().settings().getAutoForwarding()` /
  `forwardingAddresses().list()` / `filters().list()` / `delegates().list()` /
  `sendAs().list()` for `compromise_sweep`, and `users().getProfile()` for the
  `health_check` Gmail probe.
  The only write is `users().signOut()` (Directory API), issued solely by
  `sign_out_user` — which exists only when the server starts with
  `GWSADM_ENABLE_SIGN_OUT=1`. `workspace_status` also GETs Google's public
  status feed without a credential.
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

- **Read-only.** Every tool exercised here reads an audit log or a directory
  snapshot; nothing in Workspace is changed (`sign_out_user` is skipped). `daily_brief_start` creates a job inside the
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
