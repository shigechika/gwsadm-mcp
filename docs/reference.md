# Reference

## Tool index

| Tool | Description |
|------|-------------|
| `health_check` | Server version, config path, and per-domain auth probe — call at session start or after a timeout |
| `login_audit` | Reports API `login` — accounts **auto-disabled by Google** (`account_disabled_*`: leaked password, hijacked, spamming), suspicious logins, failure top-N |
| `suspended_accounts` | Directory API — current snapshot of **suspended** accounts (`isSuspended=true`); cross-reference against a downstream IdP (e.g. KeyCloak) to find suspended-but-still-enabled accounts |
| `get_user` | Directory API `users().get` — **one named account's** current state: `suspended` (with reason and time), `archived`, `last_login`, 2SV enrolled/enforced, org unit, creation time, pending password change. The "why can't this person sign in" lookup: one request, no pagination, for an address you already know — unlike `suspended_accounts`, which lists only accounts that ARE suspended, so it can never confirm that a given address is *not* suspended. Needs no scope beyond the one `suspended_accounts` already uses |
| `user_oauth_tokens` | Directory API `tokens().list` — third-party OAuth app grants for **one user**; a compromise vector `login_audit` is blind to, since a previously-granted token needs no fresh login. Domain resolved from the username's suffix, with an optional `domain` override for alias/secondary-domain addresses |
| `drive_external_sharing` | Reports API `drive` — ACL **grants** to external addresses or domains (revocations reported separately) and visibility **transitions** into link/public exposure |
| `drive_doc_activity` | Reports API `drive` with a server-side `doc_id` filter — **one document's** owner, ACL changes, and lifecycle events. Triage companion to `drive_external_sharing`: the owner (an individual vs. a shared drive's name) disambiguates the shared-drive false-positive class |
| `shared_drive_membership_changes` | Reports API `drive` (`shared_drive_membership_change`) — who added/removed/re-roled shared-drive members and when, with external classification of the affected member and a client-side drive-name filter |
| `gmail_message_trace` | Gmail API — did a **known** Message-ID reach **specific** mailboxes, and where (inbox/spam/trash/archived)? For each recipient it impersonates that user via DWD and searches their own mailbox. Requires the separate `gmail.readonly` DWD scope; a domain missing that grant reports a per-recipient error, never a false "not found" |
| `group_delivery_policy` | Groups Settings API — a Google Group's own posting/delivery policy (`who_can_post`, `allow_external_members`, moderation levels). Requires the separate `apps.groups.settings` DWD scope |
| `list_group_members` | Directory API — a Google Group's basic metadata and member roster, resolved directly rather than inferred from who happened to receive one particular message. Requires the separate `admin.directory.group.readonly` and `admin.directory.group.member.readonly` DWD scopes |
| `daily_brief` | One-call summary across all configured domains |
| `daily_brief_start` / `daily_brief_result` | Same as `daily_brief`, run in the background: `start` returns a `job_id` immediately, then poll `result(job_id)` until `done`. Use on large tenants where the synchronous call risks the client's ~60s tool-call timeout |

Planned: `dlp_events` (Reports `rules`; requires a Workspace edition with
DLP), `token_events`, `admin_events`.

## Auth-model scope table

The base pass — grant all three on the same service-account client ID up
front:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`, `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes`, `daily_brief*` | those tools degrade to a per-domain error |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`, `get_user` | those two tools degrade to an error (per-domain for `suspended_accounts`); everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | that tool degrades to a per-domain error; everything else keeps working |

Four more scopes, each granted separately — none bundled with each other or
with the base pass:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace` | that tool reports a per-recipient error; everything else keeps working |
| `https://www.googleapis.com/auth/apps.groups.settings` | `group_delivery_policy` | that tool degrades to an error; everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | `list_group_members` (group metadata half) | that half reports its own error; the member-roster half still works independently if its own scope is granted |
| `https://www.googleapis.com/auth/admin.directory.group.member.readonly` | `list_group_members` (member roster half) | same, independent of the metadata half — the two calls never gate each other |

`gmail.readonly` is materially broader than the base pass: it allows reading
*message content* for any impersonated user, not just metadata. The tool
code itself only ever requests `format="metadata"` — it never reads a
message body — but the grant itself does not enforce that; weigh the
exposure against how much you actually need message-trace before turning it
on for a given domain. See the README's Auth model section for the full
narrative, including why the narrower `gmail.metadata` scope was rejected.

## Read-only surface

The only Google API calls issued anywhere in this package: `activities().list()`
(Reports API); `users().list()`, `users().get()`, `tokens().list()`,
`groups().get()`, `members().list()` (Directory API); `groups().get()`
(Groups Settings API); `messages().list()`, `messages().get()` (Gmail API,
metadata only). No insert, update, patch, or delete call exists anywhere in
the client — `write_tools` is empty by construction, not by convention.

## CLI

```bash
gwsadm-mcp --version   # Print version and exit
gwsadm-mcp --check     # Config + auth + API smoke for every domain, then exit
gwsadm-mcp             # Start MCP server (STDIO, default)
```

`--check` exit codes: `0` success, non-zero on config or auth failure.

See the repository README's Notes section for the per-tool `capped`,
`found`, and error-shape conventions each tool follows.
