# Setup

## Install

```bash
uv pip install gwsadm-mcp
# or
pip install gwsadm-mcp
```

Or from source:

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp
uv sync          # or: pip install -e .
```

## Auth model

Service account with **domain-wide delegation (DWD)** impersonating an
audit-capable admin. Fully non-interactive — no browser, no token-refresh
rotation — so the server runs unattended (cron, MCP gateway, CI).

Grant **all** of the following DWD scopes on the same service-account client
ID up front, in one setup pass. Adding them one at a time as each tool gets
built is how a scope goes missing until the one tool that needed it starts
degrading — one place, one pass, avoids the trap:

| Scope | Needed by | Missing it |
|-------|-----------|------------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`, `admin_actions`, `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes`, `daily_brief*` | those tools degrade to a per-domain error |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`, `get_user`, `sign_out_user` (opt-in; its account check) | those tools degrade to an error (per-domain for `suspended_accounts`); everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens`, `sign_out_user` (opt-in) | those tools degrade to a per-domain error; everything else keeps working |

`health_check` needs no scope at all to respond: it is the tool to call when
a grant might be missing — it probes each domain and reports the failing
auth in a structured per-domain result instead of failing itself.

!!! tip "Three more scopes, granted separately"
    `gmail_message_trace` needs `gmail.readonly` — a materially broader grant
    than the three above, since it allows reading *message content* for any
    impersonated user (the tool code itself only ever requests
    `format="metadata"`, but the grant does not enforce that). `apps.groups.settings`
    covers `group_delivery_policy`, and `admin.directory.group.readonly` /
    `admin.directory.group.member.readonly` cover the two independent halves
    of `list_group_members`. See the [Reference](reference.md) scope table
    and the README's Auth model section for the full detail on each.

`suspended_accounts`, `get_user`, and `user_oauth_tokens` all operate per
configured domain (Directory `domain=`/`userKey=`), unlike the customer-wide
Reports tools — every domain you want covered needs its own `[domain.*]`
config section.

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
`dmarc_rua_mailbox` (optional) is the real user `dmarc_rua_summary` impersonates
to read DMARC aggregate reports; `dmarc_rua_recipient` (optional) is the published
`rua=` address it searches for when that differs from the mailbox (a plus-subaddress
or a group); `dmarc_rua_mailbox = none` opts the domain out. See the README for the
full rationale.

`GWSADM_CONFIG` itself is the entire required configuration surface — there is no way
to configure the server through plain environment variables alone. Each
`service_account_file` is a second, independent file-path dependency: a
Google Cloud service-account JSON key unique to your own GCP project. Neither
file can be templated, environment-substituted, or shipped through a plugin
manifest; both must exist on the machine running the server before any tool
call succeeds. If the INI file is missing, or a domain section is missing
`service_account_file` / `subject` / `customer_id`, every tool call fails —
there is no degraded fallback for a missing config, unlike a missing scope.

Two optional extras sharpen `daily_brief`'s account-protection section
(2-Step Verification enrolled or disabled, a passkey added or removed, Advanced
Protection turned off, password or recovery address/phone edited, mail
forwarding out of the domain turned on). Neither is needed for anything else.

`GWSADM_SITES_INI` is an INI file of your own address ranges, the same format
as keycloak-mcp's `KEYCLOAK_SITES_INI` and entraadm-mcp's `ENTRAADM_SITES_INI`,
so one file can serve all three:

```ini
[HQ]
name = Head office
ipv4 = 192.0.2.0/24, 198.51.100.0/25
ipv6 = 2001:db8:1::/48
```

Each change then says which site it came from, or `external: true`. Unset,
`external` is `null` rather than `false`, so a missing table never reads as
"everything is internal". `external` on its own is not a flag: most owners
change these settings from home.

`GWSADM_IP2ASN` points at the iptoasn.com "combined" table (`ip2asn-combined.tsv`,
plain or `.gz`, PDDL; not the `u32` variant) and `GWSADM_HOME_COUNTRIES` lists the
ISO 3166-1 alpha-2 codes changes are expected to come from, separated by commas,
e.g. `JP` or `JP,US`. The server only reads the file; refresh it
yourself (weekly is plenty). Each change from outside the sites table then
carries `country` / `asn` / `as_name`, and a row is `flagged` with
`flag_reasons`:

- `foreign` — registered country outside `GWSADM_HOME_COUNTRIES`;
- `unknown_origin` — no address, or one the dataset cannot place (an origin
  that cannot be placed is not treated as home);
- `after_suspicious_login` — the same user had a suspicious login before the
  change, looking 72 hours further back than the window (works without either
  file; `null` when the row names only a profile id or every suspicious-login
  probe failed). Probes that failed outright are named in `event_errors`. When that login scan itself was partial
  or failed, `suspicious_login_coverage` says so and the section is `capped`.

Flagged rows come first, newest first. `health_check` reports both under
`sites` and `geo`; it reads the dataset's first line, so an unreadable file is an
`error` there, and a dataset older than 30 days or a missing
`GWSADM_HOME_COUNTRIES` is a `warning`.

### Opt-in sign-out (`GWSADM_ENABLE_SIGN_OUT`)

Unset, the server has no write tool. With `GWSADM_ENABLE_SIGN_OUT=1` (exactly
`1`) it also registers `sign_out_user`, which signs one account out of every
Google session (Directory API `users().signOut`). It needs two grants: the
`admin.directory.user.readonly` scope for the account check it makes first
(the one `get_user` uses) and the `admin.directory.user.security` scope for the
sign-out itself (the one `user_oauth_tokens` uses); the impersonated admin must
also hold a role that may manage user security. Set the flag
only on a deployment that asks a person to approve each call — a chat bot with
an approval button, say — and leave it unset on anything shared more widely,
such as an MCP gateway.

## Verify before wiring it into anything

```bash
gwsadm-mcp --check
```

`--check` exit codes: `0` success, non-zero on config or auth failure.
Running this once turns "the tool returns nothing" into a question you have
already answered.

## Register with an MCP client

### Claude Code (plugin)

This repository doubles as a single-plugin marketplace:

```
/plugin marketplace add shigechika/gwsadm-mcp
/plugin install gwsadm-mcp@gwsadm-mcp
```

The plugin launches `uvx gwsadm-mcp` and reads `GWSADM_CONFIG` (falls back to
`~/.config/gwsadm-mcp/config.ini`), the same variable described in
[Configuration](#configuration). `/plugin install` only wires up the server
process — it cannot create the config INI or the Google Cloud
service-account JSON key(s) it points at; both must already exist on the
machine running the plugin before any tool call will succeed.

`uvx` must be on the `PATH` of the process that runs Claude Code — a login
shell usually has it, but a GUI-launched app may not; install
[uv](https://docs.astral.sh/uv/) system-wide if the plugin fails to start.

### Claude Code (manual)

`.mcp.json` (no `env` needed when the config lives at the default path; add
`"env": { "GWSADM_CONFIG": "..." }` only for a non-default location):

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

`claude_desktop_config.json` takes the same entry under `mcpServers`. See the
repository README for the full example.

### Direct execution

```bash
gwsadm-mcp
```

## Next

[Reference](reference.md) covers every tool, the full scope table, the CLI,
and exit codes.
