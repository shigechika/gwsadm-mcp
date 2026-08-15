# gwsadm-mcp

Google Workspace **security-audit** MCP (Model Context Protocol) server —
read-only visibility into account locks, suspicious logins, and external file
sharing, built on the Admin SDK Reports API (audit activities).

Named after the admin-console viewpoint (`gwsadm` = Google Workspace admin),
sibling of [`boxadm-mcp`](https://github.com/shigechika/boxadm-mcp). This is
**not** a general-purpose Workspace MCP: it surfaces risk, it never mutates
anything.

## Tools by area

| Area | Tools |
|---|---|
| Morning patrol | `health_check`, `daily_brief`, `daily_brief_start`, `daily_brief_result` |
| Logins & accounts | `login_audit`, `suspended_accounts`, `get_user` |
| OAuth | `user_oauth_tokens` |
| Drive | `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes` |
| Gmail | `gmail_message_trace` |
| Groups | `group_delivery_policy`, `list_group_members` |

Planned: `dlp_events` (Reports `rules`; requires a Workspace edition with
DLP), `token_events`, `admin_events`.

## Design notes

**Service-account auth via domain-wide delegation (DWD), and that choice is
load-bearing.** The server impersonates an audit-capable admin through a
service account, not a human sign-in — fully non-interactive, no browser, no
token-refresh rotation, so it runs unattended from cron, an MCP gateway, or
CI.

**A capped scan discloses that it is capped.** Every result section reports
`capped: true` when a window exceeded its page budget, or when a probe's
fetch errored outright — partial coverage is never presented as "no
findings". The Drive tools go further and record exactly which event types
were cut short.

**Read-only by construction, not by convention.** The only Google API calls
issued anywhere in this package are `activities().list()` (Reports API),
`users().list()` / `users().get()` / `tokens().list()` / `groups().get()` /
`members().list()` (Directory API), `groups().get()` (Groups Settings API),
and `messages().list()` / `messages().get()` (Gmail API, metadata only). No
insert, update, patch, or delete call exists in the client — there is no
scope grant that turns this server into a write tool.

## Next steps

- [Setup](setup.md) — install, DWD scopes, the `[domain.*]` config file, and
  registering with an MCP client
- [Reference](reference.md) — every tool, the auth-model scope table, CLI,
  exit codes
