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
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`, `drive_external_sharing`, `drive_doc_activity`, `shared_drive_membership_changes`, `daily_brief*` | those tools degrade to a per-domain error |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`, `get_user` | those two tools degrade to an error (per-domain for `suspended_accounts`); everything else keeps working |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | that tool degrades to a per-domain error; everything else keeps working |

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
```

One `[domain.*]` section per audited Workspace domain. `internal_domains` is
the allowlist used to classify sharing targets as internal vs external.

`GWSADM_CONFIG` itself is the entire configuration surface — there is no way
to configure the server through plain environment variables alone. Each
`service_account_file` is a second, independent file-path dependency: a
Google Cloud service-account JSON key unique to your own GCP project. Neither
file can be templated, environment-substituted, or shipped through a plugin
manifest; both must exist on the machine running the server before any tool
call succeeds. If the INI file is missing, or a domain section is missing
`service_account_file` / `subject` / `customer_id`, every tool call fails —
there is no degraded fallback for a missing config, unlike a missing scope.

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
