"""gwsadm-mcp MCP server — Google Workspace security audit (read-only).

Phase 1 tools:

- ``health_check``            — fleet-standard status/service/version + per-domain auth probe
- ``login_audit``             — Google-side auto-disabled accounts, suspicious logins, failure top-N
- ``suspended_accounts``      — current snapshot of suspended accounts (Directory API)
- ``get_user``                — one named account's state: suspended/archived/2SV/last login
  (Directory API; same ``admin.directory.user.readonly`` scope as ``suspended_accounts``)
- ``user_oauth_tokens``       — third-party OAuth app grants for one user (Directory API)
- ``gmail_message_trace``     — did a known Message-ID reach specific mailboxes, and where
  (Gmail API; requires the separate ``gmail.readonly`` DWD scope — see its docstring)
- ``group_delivery_policy``   — a Google Group's own posting/delivery policy (who_can_post,
  allow_external_members) — why external mail silently never arrives (Groups Settings API;
  requires the separate ``apps.groups.settings`` DWD scope — see its docstring)
- ``list_group_members``      — a Google Group's metadata + member roster, independent of any
  message ever sent to it (Directory API; requires the separate ``admin.directory.group.readonly``
  and ``admin.directory.group.member.readonly`` DWD scopes — see its docstring)
- ``drive_external_sharing``  — Drive ACL grants to external targets and new link/public exposure
- ``drive_doc_activity``      — one document's owner + ACL/lifecycle history (finding triage)
- ``shared_drive_membership_changes`` — who added/removed shared-drive members, and when
- ``daily_brief``             — one-call summary of the Reports-based tools
  (``login_audit`` + ``drive_external_sharing``) across all configured domains;
  ``suspended_accounts`` is separate (different API/scope) and not included

Coverage contract: every result section carries a ``capped`` boolean when its
window was not fully scanned, so partial coverage is never mistaken for
"no findings". A failure in one domain degrades only that domain's section
(``{"error": ...}``), never the whole tool result.
"""

import asyncio
import collections
import concurrent.futures
import datetime
import os
import re
import secrets
import threading
import time

from mcp.server.fastmcp import Context, FastMCP

from gwsadm_mcp import __version__
from gwsadm_mcp.client import DomainClient, GwsAuthError, GwsError, event_parameters
from gwsadm_mcp.config import ConfigError, config_path, is_external, load_config

mcp = FastMCP("gwsadm-mcp")

# Concurrent Reports-API fetches. Each daily_brief issues ~16 independent
# (domain x eventName) activity fetches; running them serially blows past a
# gateway's request timeout. Bounded to stay within the Admin SDK Reports rate
# budget (~10 QPS); the client retries any rate-limit error with backoff.
_DEFAULT_MAX_WORKERS = 8
_MAX_WORKERS_CAP = 32


def _max_workers() -> int:
    """Worker count for the parallel fan-out, from ``GWSADM_MAX_WORKERS``.

    Clamped to 1..32. A non-integer / empty value falls back to the default
    rather than raising: this is a documented tuning knob, so a typo must not
    crash the stdio server at startup.
    """
    try:
        return max(1, min(_MAX_WORKERS_CAP, int(os.environ.get("GWSADM_MAX_WORKERS", str(_DEFAULT_MAX_WORKERS)))))
    except ValueError:
        return _DEFAULT_MAX_WORKERS


def _parallel_fetch(tasks: list[tuple], start: datetime.datetime) -> dict:
    """Fetch ``(client, application, event_name, max_pages)`` tasks concurrently.

    Returns ``{(domain, application, event_name): (items, capped) | Exception}``.
    Fetch errors are captured per task (not raised) so each caller can apply its
    own degradation policy — a ``GwsAuthError`` fails its whole domain, a plain
    ``GwsError`` only marks that one probe. Pagination within a single fetch is
    still sequential (nextPageToken), so ordering within a probe is unchanged.
    """
    results: dict = {}
    if not tasks:
        return results

    def _one(c, app, name, mp):
        return c.fetch_activities(app, start=start, event_name=name, max_pages=mp)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(tasks))) as ex:
        futs = {ex.submit(_one, c, app, name, mp): (c.domain, app, name) for (c, app, name, mp) in tasks}
        for fut in concurrent.futures.as_completed(futs):
            key = futs[fut]
            try:
                results[key] = fut.result()
            except (GwsAuthError, GwsError) as e:
                results[key] = e
    return results


# login audit log: events emitted when Google itself disables an account.
ACCOUNT_DISABLED_EVENTS = (
    "account_disabled_password_leak",
    "account_disabled_hijacked",
    "account_disabled_spamming",
    "account_disabled_spamming_through_relay",
    "account_disabled_generic",
)
SUSPICIOUS_LOGIN_EVENTS = (
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
    "gov_attack_warning",
)

# drive audit log: ACL / visibility / cross-file access-grant events relevant
# to exposure. Queried one eventName at a time so the page budget is spent on
# audit-relevant events only (an unfiltered drive query is dominated by
# view/edit noise and can starve the window).
DRIVE_ACL_EVENTS = (
    "change_user_access",
    "change_acl_editors",
    "change_document_visibility",
    "change_document_access_scope",
    "shared_drive_membership_change",
    "shared_drive_settings_change",
    "sheets_import_range_access_change",
)
# Events whose purpose is a visibility/scope change: only these feed the
# untargeted cross-check bucket. Named-grant bookkeeping events
# (change_user_access, change_acl_editors) carry the same information via a
# paired targeted event, so their untargeted siblings are duplicates — live
# data shows hundreds/day of them, all cross-internal-domain noise.
VISIBILITY_CHANGE_EVENTS = {"change_document_visibility", "change_document_access_scope"}
# change_document_visibility and change_document_access_scope report the same
# transition as simultaneous sibling events on the same doc (live data: 361 of
# 363 sampled link/public transitions, and every sampled domain-scoped grant,
# appear on BOTH names with identical time/doc_id/visibility/old_visibility) —
# classifying, exposing, or counting from both would double every domain-scope
# grant and nearly every link/public exposure. change_document_access_scope is
# canonical for classification; change_document_visibility is still fetched
# (its acl_events/events_scanned bookkeeping is unaffected) but does not drive
# external/exposure/untargeted counting. This drops the rare (~0.6% observed)
# transition visible only via change_document_visibility.
CANONICAL_VISIBILITY_EVENT = "change_document_access_scope"

# Named-grant/ACL bookkeeping events where Google emits a same-doc "owner"
# echo purely from file creation (no prior ACL history, sometimes no
# target_user at all). The self-creation-grant exclusion below must be
# scoped to ONLY these two names: change_document_access_scope (the
# CANONICAL_VISIBILITY_EVENT) and change_document_visibility have no
# target_user parameter on this API either, but their own new_value can
# legitimately be "owner" for a genuine (non-creation) visibility
# transition — excluding those names here would blind the tool's primary
# signal instead of just removing creation noise.
SELF_CREATION_GRANT_EVENTS = {"change_user_access", "change_acl_editors"}

# Document lifecycle events worth surfacing alongside the ACL events when
# reconstructing one file's history (how it came to exist, moved, or died) —
# the high-volume access noise (view/edit/download/print) is deliberately
# absent so a hot document's history is not drowned in reads.
DOC_LIFECYCLE_EVENTS = (
    "create",
    "upload",
    "copy",
    "move",
    "rename",
    "add_to_folder",
    "remove_from_folder",
    "delete",
    "trash",
    "untrash",
)

# Drive file / shared-drive ids are URL-safe token strings. The Reports API
# ``filters`` parameter is an operator expression language (comma = AND,
# ``==`` etc.), so an id is validated against this charset BEFORE being
# interpolated — a rejected id reports an input error instead of silently
# turning into a different filter expression. Tool inputs are LLM-driven and
# must be treated as adversarial.
_DOC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,200}$")

# Visibility values that expose content beyond named accounts. Google's
# "shared_externally" is deliberately absent: it is relative to the file
# OWNER's domain, so with multiple internal domains a cross-internal-domain
# grant (e.g. student domain -> staff domain) would be flagged. Named grants
# are classified against the configured internal domains via is_external()
# instead, which loses nothing: named grants always carry ``target_user``.
LINK_PUBLIC_VISIBILITY = {"people_with_link", "public_on_the_web"}

_state: dict = {"clients": None, "internal": None}


def _clients() -> tuple[list[DomainClient], set[str]]:
    """Lazily build one DomainClient per configured domain (cached)."""
    if _state["clients"] is None:
        domains, internal = load_config()
        _state["clients"] = [DomainClient(d) for d in domains]
        _state["internal"] = internal
    return _state["clients"], _state["internal"]


def _select(clients: list[DomainClient], domain: str | None) -> list[DomainClient]:
    if domain is None:
        return clients
    picked = [c for c in clients if c.domain == domain.strip().lower()]
    if not picked:
        raise GwsError(f"unknown domain '{domain}' (configured: {[c.domain for c in clients]})")
    return picked


def _domain_of(username: str) -> str:
    """Return the lowercased domain of an email-shaped username, validating the shape.

    Rejects anything that would reach the Directory API as a malformed
    ``userKey`` (missing/empty local or domain part, embedded whitespace) so
    the caller reports a clear input error instead of a misleading
    "directory API error" from Google, or an "unknown domain ''" from
    ``_select`` for an empty suffix.
    """
    local, sep, domain = username.rpartition("@")
    if not sep or not local or not domain or any(ch.isspace() for ch in username):
        raise GwsError(f"'{username}' is not an email address")
    return domain.lower()


def _window(hours: int) -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)


def _entry(item: dict, event: dict) -> dict:
    actor = item.get("actor", {})
    return {
        "time": item.get("id", {}).get("time"),
        # profileId is a numeric fallback: some restricted/system-initiated
        # events (observed on suspicious_login) omit actor.email entirely.
        "user": actor.get("email") or actor.get("profileId"),
        # ipAddress lives on the activity item itself, not under actor, and
        # is populated far more reliably than actor.email — keep it even
        # when user is unresolvable so the entry is still investigable.
        "ip": item.get("ipAddress"),
        "event": event.get("name"),
    }


def _new_values(p: dict) -> list:
    v = p.get("new_value")
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _scalar(v):
    """Collapse an unexpectedly multi-valued parameter to its first value.

    The Reports API documents these parameters as single-valued; tolerate a
    multiValue delivery instead of failing the whole tool call on an
    unhashable list.
    """
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _scalar_lower(v):
    """``_scalar`` plus case-fold, for the address/role fields compared
    case-insensitively (target_user, target_domain, actor email)."""
    v = _scalar(v)
    return v.lower() if isinstance(v, str) else v


def _is_revocation(p: dict) -> bool:
    """True when an ACL change removes access (``new_value`` is only ``none``).

    Cleaning up an external share must not be reported as new exposure.
    """
    values = _new_values(p)
    return bool(values) and all(str(x).lower() == "none" for x in values)


@mcp.tool()
def health_check() -> dict:
    """Report service status, version, and per-domain auth/API reachability.

    Always returns the same keys: status (healthy / degraded / error), service,
    version, config, and domains (per-domain auth result). Lightweight: one
    1-item login query per domain.
    """
    base = {"service": "gwsadm-mcp", "version": __version__, "config": config_path()}
    try:
        clients, _ = _clients()
    except ConfigError as e:
        return {**base, "status": "error", "detail": str(e), "domains": []}
    results = [c.check() for c in clients]
    ok = sum(1 for r in results if r.get("auth") == "ok")
    status = "healthy" if ok == len(results) else ("degraded" if ok else "error")
    return {**base, "status": status, "domains": results}


def _aggregate_login(fetched: dict, domain: str, names: tuple) -> dict:
    """Aggregate pre-fetched login probes for one domain into {entries, capped[, event_errors]}.

    ``fetched`` comes from :func:`_parallel_fetch`. A ``GwsAuthError`` for any
    probe is re-raised so the caller degrades the whole domain (auth is
    domain-wide); a plain ``GwsError`` is recorded per event and skipped.
    """
    entries: list[dict] = []
    capped = False
    errors: dict = {}
    for name in names:
        r = fetched[(domain, "login", name)]
        if isinstance(r, GwsAuthError):
            raise r
        if isinstance(r, GwsError):
            errors[name] = str(r)
            continue
        items, c_capped = r
        for it in items:
            for ev in it.get("events", []):
                if ev.get("name") == name:
                    entries.append(_entry(it, ev))
        capped = capped or c_capped
    out = {"entries": entries, "capped": capped}
    if errors:
        out["event_errors"] = errors
    return out


def _login_audit(clients: list[DomainClient], hours: int, include_failures: bool, top: int) -> dict:
    start = _window(hours)
    # Fan out every (domain x login-event) probe at once, then aggregate serially.
    tasks: list[tuple] = []
    for c in clients:
        for name in ACCOUNT_DISABLED_EVENTS + SUSPICIOUS_LOGIN_EVENTS:
            tasks.append((c, "login", name, 2))
        if include_failures:
            tasks.append((c, "login", "login_failure", 5))
    fetched = _parallel_fetch(tasks, start)
    out: dict = {}
    for c in clients:
        try:
            dom: dict = {
                "account_disabled": _aggregate_login(fetched, c.domain, ACCOUNT_DISABLED_EVENTS),
                "suspicious_logins": _aggregate_login(fetched, c.domain, SUSPICIOUS_LOGIN_EVENTS),
            }
            if include_failures:
                r = fetched[(c.domain, "login", "login_failure")]
                if isinstance(r, (GwsAuthError, GwsError)):
                    raise r
                items, capped = r
                counts = collections.Counter(it.get("actor", {}).get("email") or "(unknown)" for it in items)
                dom["login_failures"] = {
                    "total": len(items),
                    "capped": capped,
                    "top": [{"user": u, "count": n} for u, n in counts.most_common(top)],
                }
            out[c.domain] = dom
        except (GwsAuthError, GwsError) as e:
            out[c.domain] = {"error": str(e)}
    return out


@mcp.tool()
def login_audit(hours: int = 24, domain: str | None = None, include_failures: bool = True, top: int = 10) -> dict:
    """Audit the login log: Google-auto-disabled accounts, suspicious logins, failure top-N.

    account_disabled_* events are how Google reports that IT locked an account
    (leaked password, hijacking, spamming). Combine with a Directory
    suspended-users snapshot (Phase 2) for current state. Each section carries
    ``capped`` (window not fully scanned) — treat counts as lower bounds then.
    """
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    return {"window_hours": hours, "domains": _login_audit(picked, hours, include_failures, top)}


def _suspended_entry(u: dict) -> dict:
    """Project a Directory user record to the fields relevant to a suspension audit."""
    return {
        "email": u.get("primaryEmail"),
        "suspension_reason": u.get("suspensionReason"),
        "last_login": u.get("lastLoginTime"),
        "created": u.get("creationTime"),
        "org_unit": u.get("orgUnitPath"),
    }


@mcp.tool()
def suspended_accounts(domain: str | None = None, max_pages: int = 20) -> dict:
    """Snapshot of currently suspended Google Workspace accounts, per domain.

    A suspended-but-still-provisioned account is a common attack surface: an
    account disabled in Google may remain enabled in a downstream IdP (e.g.
    KeyCloak), where a password-spray attacker can still authenticate through
    it. Cross-reference this list against the IdP to find and disable such gaps.

    Unlike ``login_audit`` (which reports the *event* of Google disabling an
    account within a time window), this is current *state* — every account
    suspended right now, regardless of when. Read-only (Directory API
    ``users().list`` with ``query=isSuspended=true``). Requires the
    ``admin.directory.user.readonly`` DWD scope; a domain missing that grant
    degrades to ``{"error": ...}`` for that domain only. ``capped`` is set when
    ``max_pages`` was hit before the listing was exhausted.

    Coverage is per configured domain (Directory ``domain=`` filter), unlike the
    customer-wide Reports tools — every domain you want covered (e.g. a separate
    student domain) must have its own ``[domain.*]`` config section, or its
    suspended accounts are not listed.

    Args:
        domain: Restrict to one configured domain (default: all).
        max_pages: Page cap (500 accounts/page); ``capped=true`` means more exist.
    """
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    out: dict = {}
    for c in picked:
        try:
            users, capped = c.list_suspended_users(max_pages=max_pages)
            out[c.domain] = {
                "count": len(users),
                "capped": capped,
                "accounts": [_suspended_entry(u) for u in users],
            }
        except (GwsAuthError, GwsError) as e:
            out[c.domain] = {"error": str(e)}
    return {"domains": out}


def _user_entry(u: dict) -> dict:
    """Project a Directory user record to the fields that explain a sign-in problem.

    Deliberately not the raw resource: a user record also carries addresses,
    phone numbers, custom schemas, photo URLs and recovery contacts, none of
    which a sign-in triage needs and all of which this tool would otherwise
    hand to a caller (and to whatever model is reading its output).

    Field names match ``_suspended_entry`` wherever the two overlap (``email``,
    ``suspension_reason``, ``last_login``, ``created``, ``org_unit``), so the
    per-user and domain-wide views of the same underlying record read alike.

    An absent field stays ``None`` rather than being coerced — the same rule
    ``group_delivery_policy`` follows. That matters most for ``suspended`` and
    ``archived``: defaulting a missing boolean to ``False`` would report "this
    account is fine" from a response that never said so.
    """
    # name is an object (givenName/familyName/fullName); guard the whole thing
    # rather than assume it is present, since every field here is optional.
    name = u.get("name") or {}
    return {
        "id": u.get("id"),
        # Google's canonical primaryEmail, which differs from the address that
        # was asked about when an alias was looked up — that difference is
        # itself worth seeing in a triage answer.
        "email": u.get("primaryEmail"),
        "name": name.get("fullName"),
        "suspended": u.get("suspended"),
        "suspension_reason": u.get("suspensionReason"),
        "suspension_time": u.get("suspensionTime"),
        "archived": u.get("archived"),
        "archival_time": u.get("archivalTime"),
        "last_login": u.get("lastLoginTime"),
        "created": u.get("creationTime"),
        "change_password_at_next_login": u.get("changePasswordAtNextLogin"),
        "is_enrolled_in_2sv": u.get("isEnrolledIn2Sv"),
        "is_enforced_in_2sv": u.get("isEnforcedIn2Sv"),
        "org_unit": u.get("orgUnitPath"),
    }


@mcp.tool()
def get_user(username: str, domain: str | None = None) -> dict:
    """Look up ONE named account's current state — the "why can't this person sign in" tool.

    Answers a helpdesk ticket that already names the exact address: is the
    account suspended (and for what reason, since when), archived, enrolled in
    or enforced into 2-step verification, when did it last log in, which org
    unit is it in, is a password change pending. One Directory API request, no
    pagination.

    Use this — not ``suspended_accounts`` — whenever the address is known.
    That tool enumerates every suspended account in the domain and stops at
    its page cap, so on a large tenant it can return without ever reaching the
    account being asked about, which reads as "cannot be determined" after
    spending far more API calls than this. ``suspended_accounts`` is for the
    domain-wide sweep it is actually named for.

    An address that names no account returns ``found: false`` with no state
    fields. That is a normal, expected answer — a typo'd or long-deleted
    address — and is itself the diagnostic result, NOT a failure. A missing
    DWD scope, a rejected credential or a transient API failure is reported as
    ``{"error": ...}`` instead. The two are deliberately distinct: never read
    ``found: false`` as "the lookup did not work", and never read an ``error``
    as evidence about whether the account exists.

    Read-only (Directory API ``users().get``; no mutating method exists in
    this package). Requires the ``admin.directory.user.readonly`` DWD scope —
    the same one ``suspended_accounts`` uses, so a tenant already running that
    tool needs no additional grant.

    Args:
        username: Exact user email, passed through as the Directory API
            ``userKey`` (primary or alias address both work on Google's side;
            the returned ``email`` is the account's canonical primary one).
        domain: Configured ``[domain.*]`` section to route the lookup through.
            Default: resolved from the username's suffix. Set it explicitly
            when the address uses an alias/secondary domain that has no
            config section of its own (common when copying addresses from
            mail headers or IdP logs).
    """
    username = username.strip()
    try:
        # Validate the input shape before touching config: a typo'd email on a
        # server with a broken config should report the typo, not ConfigError.
        suffix = _domain_of(username)
        clients, _ = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"username": username, "error": str(e)}
    c = picked[0]
    try:
        user = c.get_user(username)  # None means "no such account", not a failure
    except (GwsAuthError, GwsError) as e:
        return {"domain": c.domain, "username": username, "error": str(e)}
    if user is None:
        return {"domain": c.domain, "username": username, "found": False}
    return {"domain": c.domain, "username": username, "found": True, **_user_entry(user)}


def _token_entry(t: dict) -> dict:
    """Project a Directory Tokens resource to the fields relevant to triage."""
    return {
        "client_id": t.get("clientId"),
        "display_text": t.get("displayText"),
        "scopes": t.get("scopes", []),
        "anonymous": t.get("anonymous"),
        "native_app": t.get("nativeApp"),
    }


@mcp.tool()
def user_oauth_tokens(username: str, domain: str | None = None) -> dict:
    """List third-party OAuth apps one user has granted account access to.

    Account-compromise triage tool for the case ``login_audit`` and
    ``suspended_accounts`` are both blind to: a malicious app used a
    previously-granted OAuth token to read/delete mail or Drive files without
    ever generating a fresh login event. Check each entry's ``scopes`` for
    Gmail/Drive access on an unrecognized ``client_id``/``display_text`` —
    Google's own apps (e.g. iOS/Android account sync) show up too and are
    normal noise.

    Read-only (Directory API ``tokens().list``; never ``tokens().delete()``).
    Requires the ``admin.directory.user.security`` DWD scope — distinct from
    ``admin.directory.user.readonly`` used by ``suspended_accounts``; a domain
    missing that grant returns ``{"error": ...}``. No pagination: the API
    returns a user's full grant list in one response.

    Args:
        username: Exact user email, passed through as the Directory API
            ``userKey`` (primary or alias address both work on Google's side).
        domain: Configured ``[domain.*]`` section to route the lookup through.
            Default: resolved from the username's suffix. Set it explicitly
            when the address uses an alias/secondary domain that has no
            config section of its own (common when copying addresses from
            mail headers or IdP logs).
    """
    username = username.strip()
    try:
        # Validate the input shape before touching config: a typo'd email on a
        # server with a broken config should report the typo, not ConfigError.
        suffix = _domain_of(username)
        clients, _ = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"username": username, "error": str(e)}
    c = picked[0]
    try:
        tokens = c.list_user_oauth_tokens(username)
    except (GwsAuthError, GwsError) as e:
        return {"domain": c.domain, "username": username, "error": str(e)}
    return {
        "domain": c.domain,
        "username": username,
        "count": len(tokens),
        "tokens": [_token_entry(t) for t in tokens],
    }


# gmail_message_trace: hard cap on recipients per call. This is a per-recipient
# DWD-impersonated Gmail search (2 API calls each), not a bulk/paged listing, so
# there is no natural "capped" partial-result concept the way the Reports-based
# tools have -- a caller asking about more recipients than this either splits the
# request or is handed a clear error, never a silently truncated list.
MAX_TRACE_RECIPIENTS = 50

# find_message_by_id interpolates this straight into a Gmail search query
# (``rfc822msgid:<id>``), an operator-language string like the Reports
# ``filters`` expression ``_DOC_ID_RE`` guards above -- so it gets the same
# treatment: validated against a charset BEFORE being interpolated, rather
# than trusting a caller-supplied id not to contain whitespace or Gmail
# search syntax (``OR``, ``from:...``) that would silently broaden the
# search to unrelated messages. Tool inputs are LLM-driven and must be
# treated as adversarial.
#
# The charset is RFC 5322 dot-atom-text (section 3.6.4's id-left/id-right):
# ALPHA / DIGIT / "!#$%&'*+-/=?^_`{|}~", with "." allowed only between
# atoms (no leading/trailing/doubled dot) -- e.g. "abc/def=123@example.edu"
# is a legitimate Message-ID under this grammar despite the "/" and "=".
# Deliberately narrower than the full RFC: no whitespace, no quoted-string
# local part, no "[...]" domain literal -- none of those appear in
# Message-IDs auto-generated by real mail systems, and the exclusions are
# exactly what keeps this a validator rather than a pass-through.
_ATEXT = r"[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]"
_MESSAGE_ID_RE = re.compile(rf"^{_ATEXT}+(?:\.{_ATEXT}+)*@{_ATEXT}+(?:\.{_ATEXT}+)*$")


def _parse_recipients(raw: str) -> list[str]:
    """Split a comma/whitespace-separated recipient list, de-duplicated
    case-insensitively (Gmail treats an address's casing as insignificant),
    order preserved, first-seen casing kept."""
    parts = re.split(r"[,\s]+", raw.strip())
    seen: dict[str, str] = {}
    for p in parts:
        p = p.strip()
        if p:
            seen.setdefault(p.casefold(), p)
    return list(seen.values())


def _classify_folder(label_ids: list[str]) -> str:
    """Map Gmail's raw label set to the one-word answer an incident report wants."""
    if "TRASH" in label_ids:
        return "trash"
    if "SPAM" in label_ids:
        return "spam"
    if "INBOX" in label_ids:
        return "inbox"
    return "archived"  # exists, but the user filed/archived it out of all three


@mcp.tool()
def gmail_message_trace(message_id: str, recipients: str, domain: str | None = None) -> dict:
    """Check whether a message (by RFC 822 Message-ID) reached specific users' mailboxes.

    Answers "who got this email and who didn't" for a KNOWN Message-ID and a
    KNOWN candidate recipient list — there is no Workspace API to search
    across every user for one message, so the caller supplies who to check
    (a mailing-list roster, or simply the people who reported a problem).
    For each recipient this impersonates that exact user via domain-wide
    delegation and searches their own mailbox (including Spam and Trash) for
    the Message-ID.

    Requires the ``gmail.readonly`` DWD scope — granted PER SERVICE ACCOUNT
    CLIENT ID in the Admin console (Security > API controls > Domain-wide
    delegation), separately from the ``admin.directory.*`` / ``admin.reports.*``
    scopes the rest of this server uses, and NOT on by default. A domain
    missing that grant reports a per-recipient ``error`` rather than a
    silent "not found" — the two must never be confused, since "not found"
    here can also legitimately mean the message was delivered and later
    deleted by the user, or never delivered at all; this tool cannot tell
    those apart, only "a match currently exists in this mailbox" from "it
    doesn't".

    Read-only: only ``messages().list`` and ``messages().get`` (metadata
    only, never the message body) are issued against each impersonated
    mailbox — see ``DomainClient.find_message_by_id``.

    A per-recipient result sets ``ambiguous: true`` (with ``match_count``)
    when more than one message in that mailbox shares the Message-ID (e.g. a
    mailing-list copy plus a direct CC) — the other fields describe only the
    first match in that case, not a combined answer. ``match_count_capped``
    is set alongside it when the mailbox has enough matches that
    ``match_count`` itself is a lower bound, not exact.

    Args:
        message_id: The RFC 822 Message-ID to search for, with or without
            angle brackets. Must be shaped like an address (``local@domain``,
            no whitespace) — this is validated before use, since it is
            interpolated into a Gmail search query.
        recipients: Comma- and/or whitespace-separated exact recipient email
            addresses to check (max 50 per call — split a larger list across
            multiple calls rather than expecting a partial result).
        domain: Configured ``[domain.*]`` section to route EVERY recipient
            through. Default: resolved per-recipient from their own address
            suffix, so one call can cover a mixed staff/student list. Set
            this only when recipients use an alias/secondary domain with no
            config section of its own.
    """
    stripped_id = message_id.strip().strip("<>")
    if not _MESSAGE_ID_RE.match(stripped_id):
        return {
            "message_id": stripped_id,
            "error": "message_id is not a valid RFC 822 Message-ID (local@domain expected)",
        }
    addrs = _parse_recipients(recipients)
    if not addrs:
        return {"message_id": stripped_id, "error": "no recipients given"}
    if len(addrs) > MAX_TRACE_RECIPIENTS:
        return {
            "message_id": stripped_id,
            "error": f"{len(addrs)} recipients exceeds the {MAX_TRACE_RECIPIENTS}-per-call limit; split the list",
        }

    try:
        clients, _ = _clients()
    except ConfigError as e:
        return {"message_id": stripped_id, "error": str(e)}

    def _one(addr: str):
        suffix_or_err = None
        try:
            suffix_or_err = _domain_of(addr)
            picked = _select(clients, domain if domain is not None else suffix_or_err)
        except GwsError as e:
            return {"error": str(e)}
        c = picked[0]
        try:
            found = c.find_message_by_id(addr, stripped_id)
        except (GwsAuthError, GwsError) as e:
            return {"domain": c.domain, "error": str(e)}
        if found is None:
            return {"domain": c.domain, "found": False}
        result = {
            "domain": c.domain,
            "found": True,
            "folder": _classify_folder(found["label_ids"]),
            "label_ids": found["label_ids"],
            "date": found["headers"].get("Date"),
            "internal_date": found["internal_date"],
            "snippet": found["snippet"],
        }
        if found["match_count"] > 1:
            # More than one message in this mailbox shares the Message-ID
            # (mailing-list + direct CC, a forwarding rule, a quarantine
            # release copy); the fields above describe only the first
            # match, so flag it rather than presenting one copy's folder as
            # the definitive answer.
            result["ambiguous"] = True
            result["match_count"] = found["match_count"]
            if found["match_count_capped"]:
                # match_count itself is a lower bound here (the underlying
                # list() call does not paginate) -- say so rather than
                # implying an exact count.
                result["match_count_capped"] = True
        return result

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(addrs))) as ex:
        futs = {ex.submit(_one, addr): addr for addr in addrs}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()

    found_n = sum(1 for r in results.values() if r.get("found") is True)
    not_found_n = sum(1 for r in results.values() if r.get("found") is False)
    error_n = sum(1 for r in results.values() if "error" in r)
    return {
        "message_id": stripped_id,
        "recipients_checked": len(addrs),
        "found": found_n,
        "not_found": not_found_n,
        "errors": error_n,
        # Keyed by the recipient address as given, in the de-duplicated
        # input order -- this dict comprehension re-inserts in that order,
        # which Python 3.7+ dict iteration preserves. ThreadPoolExecutor
        # completion order (the order `results` above was actually built in)
        # is NOT deterministic, so this re-keying is what guarantees "same
        # order as input" rather than incidental luck.
        "results": {addr: results[addr] for addr in addrs},
    }


@mcp.tool()
def group_delivery_policy(group_email: str, domain: str | None = None) -> dict:
    """Check a Google Group's own posting/delivery policy — why an external sender's mail never arrived.

    A Group's access-control layer sits IN FRONT of Gmail delivery: when
    ``who_can_post`` is restricted (e.g. domain-members-only), an external
    sender's message is rejected there and never generates a per-recipient
    Gmail delivery event at all — ``gmail_message_trace`` (a real mailbox) and
    any Reports-API-based delivery trace both see nothing for that address,
    indistinguishable from a genuine delivery failure without this. Use this
    FIRST when a group address "isn't receiving" mail from an external
    sender, before chasing it as a transport/spam problem.

    Read-only: only ``groups().get()`` is issued (Groups Settings API).
    Requires the ``apps.groups.settings`` DWD scope — granted PER SERVICE
    ACCOUNT CLIENT ID in the Admin console (Security > API controls >
    Domain-wide delegation), separately from every other scope this server
    uses, and NOT on by default.

    Returns ``who_can_post`` (e.g. ``ALL_IN_DOMAIN_CAN_POST`` blocks external
    senders entirely; ``ANYONE_CAN_POST`` allows them), ``allow_external_members``,
    ``is_archived``, ``message_moderation_level``, ``spam_moderation_level``,
    ``allow_web_posting``. Sets ``found: false`` (no policy fields) when
    ``group_email`` does not name any group in this domain — that is a
    normal, expected answer for a bad/typo'd address, not an ``error``.

    Args:
        group_email: The group's address (e.g. "team.gen@example.edu").
        domain: Configured ``[domain.*]`` section to route the lookup through.
            Default: resolved from the address's suffix.
    """
    group_email = group_email.strip()
    try:
        suffix = _domain_of(group_email)
        clients, _ = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"group_email": group_email, "error": str(e)}
    c = picked[0]
    try:
        policy = c.get_group_settings(group_email)
    except (GwsAuthError, GwsError) as e:
        return {"domain": c.domain, "group_email": group_email, "error": str(e)}
    if policy is None:
        return {"domain": c.domain, "group_email": group_email, "found": False}
    return {"domain": c.domain, "group_email": group_email, "found": True, **policy}


@mcp.tool()
def list_group_members(group_email: str, domain: str | None = None, max_pages: int = 20) -> dict:
    """List a Google Group's basic metadata and member roster (Directory API).

    Resolves a group's actual membership directly, independent of any
    specific message ever having been sent to it — unlike inferring
    membership from Reports API delivery-event fanout (``applicationName=gmail``),
    which only shows members who received one PARTICULAR message and
    requires one to already exist to trace. Pair with ``gmail_message_trace``
    to deep-dive a specific member's mailbox once the roster is known, or
    with ``group_delivery_policy`` to see why the group as a whole may not be
    receiving mail at all.

    Read-only: only ``groups().get()`` and ``members().list()`` are issued
    (Directory API), never a mutating call. Requires the
    ``admin.directory.group.readonly`` and
    ``admin.directory.group.member.readonly`` DWD scopes — granted PER
    SERVICE ACCOUNT CLIENT ID in the Admin console, separately from every
    other scope this server uses, and NOT on by default. The two calls are
    independent: a tenant with only one of the two scopes granted still gets
    that one section, with the other reported as ``{"error": ...}`` in its
    place rather than failing the whole call — only when BOTH fail does the
    tool return a single top-level ``error``.

    Sets ``found: false`` (no ``group``/``members`` sections) when
    ``group_email`` does not name any group in this domain — a normal,
    expected answer for a bad/typo'd address, not an ``error``. This
    triggers both when BOTH calls agree with no error on either side, AND
    when one call CONFIRMS not-found while the other independently failed
    (its own error is then attached as ``group_lookup_error`` /
    ``members_lookup_error``) — a confirmed non-existence from one
    independently-scoped call is stronger evidence than an unrelated
    failure on the other, and must not be buried under it.

    Args:
        group_email: The group's address.
        domain: Configured ``[domain.*]`` section to route the lookup through.
            Default: resolved from the address's suffix.
        max_pages: Pagination cap for the member roster (Directory API hard
            limit 200 members per page). Default 20 (≤4,000 members) —
            raise for an unusually large group. ``capped: true`` means the
            roster is NOT the complete one — either more pages existed
            beyond this, or the member lookup failed outright (see
            ``members_error``); either way it must never be read as the
            full membership, and an empty ``members`` list must not be
            mistaken for a confirmed-empty group when ``capped`` is true.
    """
    group_email = group_email.strip()
    try:
        suffix = _domain_of(group_email)
        clients, _ = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"group_email": group_email, "error": str(e)}
    c = picked[0]

    group = None
    group_err = None
    try:
        group = c.get_group(group_email)  # None means "no such group", not an error
    except (GwsAuthError, GwsError) as e:
        group_err = str(e)

    members: list = []
    capped = False
    members_not_found = False
    members_err = None
    try:
        roster = c.list_group_members(group_email, max_pages=max_pages)
        if roster is None:
            members_not_found = True
        else:
            members, capped = roster
    except (GwsAuthError, GwsError) as e:
        members_err = str(e)

    if group_err is not None and members_err is not None:
        # Neither scope produced anything usable -- one combined error beats
        # two redundant per-section ones.
        return {
            "domain": c.domain,
            "group_email": group_email,
            "error": f"group lookup failed ({group_err}); member lookup failed ({members_err})",
        }
    group_not_found = group_err is None and group is None
    if group_not_found and members_not_found:
        # Both independent lookups agree, with no error on either side, that
        # this address is not a group at all -- a clean answer, not a partial
        # failure, so it gets its own shape rather than an empty group/members
        # pair that would look identical to "group exists but has 0 members".
        return {"domain": c.domain, "group_email": group_email, "found": False}
    # One side can independently CONFIRM non-existence (a 404, no exception)
    # even when the OTHER side only failed to answer (a real error, e.g. its
    # own scope missing) -- the confirmed not-found is the stronger,
    # actionable signal and must not be buried under an unrelated error from
    # a DIFFERENT scope, forcing an operator to manually cross-reference the
    # two sections to reach the same conclusion this tool already has.
    if members_not_found and group_err is not None:
        return {
            "domain": c.domain,
            "group_email": group_email,
            "found": False,
            "group_lookup_error": group_err,
        }
    if group_not_found and members_err is not None:
        return {
            "domain": c.domain,
            "group_email": group_email,
            "found": False,
            "members_lookup_error": members_err,
            # A confirmed-nonexistent group trivially has no members, but
            # the member-side call itself still failed to verify anything
            # -- carry the same capped: true marker every other incomplete-
            # coverage response uses, so a caller checking that one field
            # doesn't need a special case for this shape.
            "capped": True,
        }
    # From here on, group EXISTS (or its own lookup errored) but the member
    # roster could still be unusable two ways: a real error, OR an unpaired
    # not-found (e.g. the group was deleted between the two independent
    # calls) -- both mean "no roster was actually fetched", so both must be
    # treated alike for member_count/members/capped, not just the error case.
    members_unusable = members_err is not None or members_not_found
    members_reason = (
        members_err
        if members_err is not None
        else ("member lookup returned not-found (group may have changed between the two independent lookups)")
        if members_not_found
        else None
    )
    return {
        "domain": c.domain,
        "group_email": group_email,
        "group": ({"error": group_err} if group_err is not None else ({"found": False} if group is None else group)),
        "member_count": 0 if members_unusable else len(members),
        "members": [] if members_unusable else members,
        # A member-lookup failure fetched NO roster at all -- strictly worse
        # than a merely page-capped one, so it counts as partial coverage
        # too (same convention drive_external_sharing uses: "a probe that
        # errored out ... counts as partial coverage"). capped=False must
        # mean "this IS the complete roster", never "we don't know" -- an
        # empty group and an inaccessible one must not look identical here.
        "capped": True if members_unusable else capped,
        **({"members_error": members_reason} if members_reason is not None else {}),
    }


def _drive_sample(item: dict, event: dict, p: dict, *, target, target_domain, visibility, old_visibility) -> dict:
    return {
        **_entry(item, event),
        "doc_title": p.get("doc_title"),
        "doc_id": p.get("doc_id"),
        # Normalized values (scalar + lowercased) — matches what was counted,
        # not the raw parameter (which may be a multiValue list or mixed case).
        "target_user": target,
        "target_domain": target_domain,
        "visibility": visibility,
        "old_visibility": old_visibility,
        "new_value": p.get("new_value"),
    }


def _drive_external_sharing(
    clients: list[DomainClient], internal: set[str], hours: int, max_pages: int, samples: int
) -> dict:
    start = _window(hours)
    # Fan out every (domain x ACL-event) drive probe at once, then aggregate serially.
    fetched = _parallel_fetch([(c, "drive", name, max_pages) for c in clients for name in DRIVE_ACL_EVENTS], start)
    out: dict = {}
    for c in clients:
        try:
            by_event: collections.Counter = collections.Counter()
            external_targets: collections.Counter = collections.Counter()
            revoked = 0
            risky_visibility = 0
            untargeted_external = 0
            scanned = 0
            capped_events: list[str] = []
            errors: dict = {}
            external_sample: list[dict] = []
            exposure_sample: list[dict] = []
            untargeted_sample: list[dict] = []
            for name in DRIVE_ACL_EVENTS:
                r = fetched[(c.domain, "drive", name)]
                if isinstance(r, GwsAuthError):
                    raise r
                if isinstance(r, GwsError):
                    errors[name] = str(r)
                    continue
                items, c_capped = r
                if c_capped:
                    capped_events.append(name)
                scanned += len(items)
                for it in items:
                    for ev in it.get("events", []):
                        if ev.get("name") != name:
                            continue  # items can carry sibling events; count each under its own probe
                        by_event[name] += 1
                        p = event_parameters(ev)
                        target = _scalar_lower(p.get("target_user"))
                        target_domain = _scalar_lower(p.get("target_domain"))
                        visibility = _scalar(p.get("visibility"))
                        old_visibility = _scalar(p.get("old_visibility"))
                        # A brand-new Form/Sheet/Doc's first-ever ACL echo grants
                        # "owner" with no prior ACL history (old_visibility
                        # "unknown") — on change_user_access this names the
                        # creator as target_user; on change_acl_editors (a
                        # sibling bookkeeping event for the same creation) the
                        # target is often absent entirely. Neither is exposure
                        # of anything pre-existing, just a file being born, and
                        # both must be excluded — but a THIRD PARTY granted
                        # owner (target present and not the actor) is a real,
                        # notable event and must still count. A genuine
                        # narrow-to-wide exposure event may also report
                        # old_visibility as missing/unknown (see the "missing
                        # prior state" test); that case carries no "owner"
                        # new_value and so is unaffected by this exclusion.
                        # Scoped to SELF_CREATION_GRANT_EVENTS only: this
                        # heuristic must never reach change_document_access_scope
                        # (CANONICAL_VISIBILITY_EVENT has no target_user param
                        # either, and its new_value legitimately includes
                        # "owner" for a real transition — applying this
                        # exclusion there would blind the tool's primary signal,
                        # not just remove creation noise).
                        #
                        # When target is absent (the change_acl_editors shape),
                        # "no named target" alone is NOT proof of creation — an
                        # admin bulk-transferring ownership of a pre-existing,
                        # already-shared file (e.g. account offboarding) emits
                        # the same shape with no target_user either. Corroborate
                        # with the event's own "owner" parameter (the file's
                        # current owner): a genuine creation echo has the actor
                        # granting themselves owner of their OWN new file, so
                        # owner == actor; a third-party admin action does not.
                        # If "owner" itself is absent, we can't confirm
                        # self-action, so the conservative default is to NOT
                        # exclude (count it) rather than risk dropping a real
                        # ownership change to someone else.
                        actor_email = _scalar_lower((it.get("actor") or {}).get("email"))
                        owner = _scalar_lower(p.get("owner"))
                        is_self_creation_grant = (
                            name in SELF_CREATION_GRANT_EVENTS
                            and (old_visibility in (None, "unknown"))
                            and (
                                target == actor_email
                                if target is not None
                                else (owner is not None and owner == actor_email)
                            )
                            and any(str(v).lower() == "owner" for v in _new_values(p))
                        )
                        # See CANONICAL_VISIBILITY_EVENT: change_document_visibility
                        # is a near-100% duplicate sibling of change_document_access_scope
                        # on this API and must not independently drive classification.
                        duplicate_visibility_probe = (
                            name in VISIBILITY_CHANGE_EVENTS and name != CANONICAL_VISIBILITY_EVENT
                        )
                        if target:
                            external = is_external(target, internal)
                            ext_key = target
                        elif target_domain and target_domain != "all" and not duplicate_visibility_probe:
                            # Domain-scoped grant (e.g. "anyone at partner.edu"):
                            # classify the bare domain directly — is_external()
                            # expects an address and would misjudge it.
                            # target_domain == "all" is link/public scope and is
                            # covered by the visibility transition below.
                            external = target_domain not in internal
                            ext_key = target_domain
                        else:
                            external = False
                            ext_key = None
                        # Exposure means the document BECAME link/public-visible in
                        # this event — not an unrelated ACL touch on a document that
                        # was already exposed (old_visibility tells the prior state),
                        # and not a narrowing from public (anyone with the link, found
                        # via search) down to link-only (needs the link) — that is a
                        # reduction in exposure, not a new one.
                        became_exposed = (
                            not duplicate_visibility_probe
                            and not is_self_creation_grant
                            and visibility in LINK_PUBLIC_VISIBILITY
                            and old_visibility != visibility
                            and (old_visibility, visibility) != ("public_on_the_web", "people_with_link")
                        )
                        # shared_externally with no classifiable target cannot be
                        # judged against internal_domains. Surfaced separately so
                        # these keep providing redundant coverage when the heavy
                        # named-grant probe is page-capped. Narrowing from a
                        # link/public state down to named-external is not new
                        # exposure and is excluded.
                        untargeted = (
                            ext_key is None
                            and not duplicate_visibility_probe
                            and name in VISIBILITY_CHANGE_EVENTS
                            and visibility == "shared_externally"
                            and old_visibility != visibility
                            and old_visibility not in LINK_PUBLIC_VISIBILITY
                        )
                        if external and _is_revocation(p):
                            revoked += 1  # cleanup of an external share, not new exposure
                            continue
                        sample_kwargs = dict(
                            target=target,
                            target_domain=target_domain,
                            visibility=visibility,
                            old_visibility=old_visibility,
                        )
                        if external:
                            external_targets[ext_key] += 1
                            if len(external_sample) < samples:
                                external_sample.append(_drive_sample(it, ev, p, **sample_kwargs))
                        if became_exposed:
                            risky_visibility += 1
                            if len(exposure_sample) < samples:
                                exposure_sample.append(_drive_sample(it, ev, p, **sample_kwargs))
                        if untargeted:
                            untargeted_external += 1
                            if len(untargeted_sample) < samples:
                                untargeted_sample.append(_drive_sample(it, ev, p, **sample_kwargs))
            dom = {
                "events_scanned": scanned,
                # A probe that errored out fetched nothing for the whole
                # window — strictly worse than a merely page-capped one — so
                # it counts as partial coverage too (see event_errors for
                # which probe; change_document_access_scope failing is the
                # one case with no redundant sibling to fall back on, since
                # change_document_visibility no longer drives classification).
                "capped": bool(capped_events) or bool(errors),
                "capped_events": capped_events,
                "acl_events": dict(by_event),
                "external_targets_total": len(external_targets),
                "external_targets_top": [{"target": t, "count": n} for t, n in external_targets.most_common(10)],
                "external_access_revoked": revoked,
                "risky_visibility_events": risky_visibility,
                "untargeted_external_transitions": untargeted_external,
                "external_samples": external_sample,
                "exposure_samples": exposure_sample,
                "untargeted_samples": untargeted_sample,
            }
            if errors:
                dom["event_errors"] = errors
            out[c.domain] = dom
        except (GwsAuthError, GwsError) as e:
            out[c.domain] = {"error": str(e)}
    return out


@mcp.tool()
def drive_external_sharing(hours: int = 24, domain: str | None = None, max_pages: int = 5, samples: int = 20) -> dict:
    """Report Drive ACL grants to external targets and new link/public exposure.

    Counts grants whose target (``target_user`` address, or ``target_domain``
    for domain-scoped grants) is outside the configured internal domains
    (revocations are reported separately, not as exposure) and visibility
    transitions into link/public access (``people_with_link`` /
    ``public_on_the_web``, excluding a narrowing from public down to
    link-only; Google's ``shared_externally`` is owner-domain relative, so
    external-ness is judged by the target instead).
    ``untargeted_external_transitions`` counts transitions into
    ``shared_externally`` with no target address or domain (e.g. scope
    became "anyone with the link" — ``target_domain: "all"`` — or an
    unresolved target); it is a residual bucket, not a cross-check for
    missed named grants, since domain-scoped grants are already classified
    above. ``external_samples`` / ``exposure_samples`` / ``untargeted_samples``
    hold examples of each. A self-grant of ``owner`` on ``change_user_access``
    /``change_acl_editors`` (a user creating their own new file — every
    Form/Sheet/Doc submission does this) is excluded from
    ``risky_visibility_events``: it always reports a visibility transition
    from a missing prior state, which is indistinguishable from a genuine
    narrow-to-wide exposure event by visibility fields alone, but is not
    exposure of anything pre-existing. When no ``target_user`` is named
    (the ``change_acl_editors`` shape), a missing target alone is not proof
    of creation — an admin bulk-transferring ownership of a pre-existing,
    already-shared file (e.g. offboarding) looks the same — so this case is
    corroborated against the event's own ``owner`` parameter (self-action
    only if ``owner`` matches the actor); if ``owner`` itself is absent the
    conservative default is to count it rather than risk dropping a real
    ownership change. This exclusion is deliberately never applied to
    ``change_document_access_scope``/``change_document_visibility``
    (see ``SELF_CREATION_GRANT_EVENTS``) — those carry no ``target_user`` and
    can legitimately report ``new_value: "owner"`` for a real transition, so
    excluding them there would blind this tool's primary signal instead of
    just removing creation noise. Each audit-relevant event name is
    queried separately so the page budget is not consumed by view/edit noise
    (``change_document_visibility`` is fetched for its ``acl_events`` count
    only — it duplicates ``change_document_access_scope`` on this API and
    does not drive classification, so it cannot compensate if that probe's
    own fetch fails). ``capped_events`` lists event names that exceeded
    max_pages*1000 events; ``capped`` is also set when any probe's fetch
    errored outright (see ``event_errors``) — either way, treat that
    domain's counts as lower bounds. Narrow ``hours`` or raise ``max_pages``
    for full coverage (term-time weekdays see >10k change_user_access
    events/day).

    Shared-drive caveat: a file created INSIDE a shared drive emits
    ``change_user_access`` events for each existing drive member (ACL
    propagation), so an external member merely uploading files looks like
    bulk external sharing here. When a finding's documents share one owner
    that is a drive NAME rather than a user address, triage with
    ``drive_doc_activity`` (per-document history: the "grants" coincide with
    ``create``/``upload`` by the same actor) and
    ``shared_drive_membership_changes`` (who added the members, and when).
    """
    try:
        clients, internal = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    return {
        "window_hours": hours,
        "domains": _drive_external_sharing(picked, internal, hours, max_pages, samples),
    }


def _doc_event_entry(item: dict, event: dict, p: dict) -> dict:
    return {
        **_entry(item, event),
        "target_user": _scalar_lower(p.get("target_user")),
        "target_domain": _scalar_lower(p.get("target_domain")),
        "visibility": _scalar(p.get("visibility")),
        "old_visibility": _scalar(p.get("old_visibility")),
        "new_value": p.get("new_value"),
        "membership_change_type": _scalar(p.get("membership_change_type")),
    }


def _fetch_drive_per_domain(
    picked: list[DomainClient],
    *,
    start: datetime.datetime,
    event_name: str | None = None,
    filters: str | None = None,
    max_pages: int,
) -> dict:
    """Run one drive probe per domain concurrently (same worker pool policy as
    ``_parallel_fetch``, which cannot carry a ``filters`` expression in its task
    tuple). Returns ``{domain: (items, capped) | Exception}`` so each caller
    applies its own per-domain degradation."""
    results: dict = {}

    def _one(c: DomainClient):
        return c.fetch_activities("drive", start=start, event_name=event_name, filters=filters, max_pages=max_pages)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(picked))) as ex:
        futs = {ex.submit(_one, c): c.domain for c in picked}
        for fut in concurrent.futures.as_completed(futs):
            dom = futs[fut]
            try:
                results[dom] = fut.result()
            except (GwsAuthError, GwsError) as e:
                results[dom] = e
    return results


@mcp.tool()
def drive_doc_activity(
    doc_id: str, days: int = 180, domain: str | None = None, max_pages: int = 5, max_events: int = 100
) -> dict:
    """Full audit history of one Drive document: owner, ACL changes, lifecycle.

    The triage companion to ``drive_external_sharing``: a sharing finding names
    a ``doc_id``, and judging it requires who OWNS the document (an individual
    user vs. a shared drive completely changes the risk read) and its grant
    history over time. Uses a server-side ``doc_id`` filter, so the page budget
    is spent on this one document only.

    ``owner`` / ``doc_title`` are taken from the document's own events (a
    shared-drive-owned file reports the drive's name — not a user address — as
    owner). ``events`` lists ACL and lifecycle events newest-first
    (view/edit/download noise is counted in ``event_counts`` but not listed);
    ``events_truncated`` is set when more matched than ``max_events``.
    The ``doc_id`` filter matches at the ACTIVITY level and one activity can
    carry sibling events for OTHER documents (a multi-file share is one
    activity with one event per file) — events whose own ``doc_id`` parameter
    does not match (or is absent) are excluded from every output field and
    tallied in ``sibling_events_skipped`` instead, so a bulk action cannot
    contaminate this document's history or misattribute its owner.
    An empty result means no events in the window for the queried tenant —
    NOT proof the document does not exist (history older than the Reports API
    retention, or a document living in a different tenant, looks the same).

    Args:
        doc_id: Drive document id (from a sharing finding's ``doc_id`` field).
        days: How far back to scan (Reports API retains roughly 6 months).
        domain: Restrict to one configured domain/tenant (default: all).
        max_pages: Reports page cap per domain; ``capped=true`` means more existed.
        max_events: Cap on listed events (counts are unaffected).
    """
    doc_id = doc_id.strip()
    if not _DOC_ID_RE.match(doc_id):
        return {"doc_id": doc_id, "error": "doc_id is not a valid Drive id (URL-safe token expected)"}
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"doc_id": doc_id, "error": str(e)}
    start = _window(days * 24)
    relevant = set(DRIVE_ACL_EVENTS) | set(DOC_LIFECYCLE_EVENTS)
    # filters-without-eventName semantics verified live (2026-07-24): a bare
    # "doc_id==<id>" filter applies across event types — one real document
    # returned exactly its create / change_user_access / add_to_folder events
    # and nothing else, matching an unfiltered scan of the same document.
    fetched = _fetch_drive_per_domain(picked, start=start, filters=f"doc_id=={doc_id}", max_pages=max_pages)
    out: dict = {}
    for c in picked:
        r = fetched[c.domain]
        if isinstance(r, Exception):
            out[c.domain] = {"error": str(r)}
            continue
        items, capped = r
        counts: collections.Counter = collections.Counter()
        entries: list[dict] = []
        truncated = False
        siblings_skipped = 0
        owner = None
        title = None
        for it in items:
            for ev in it.get("events", []):
                p = event_parameters(ev)
                # The doc_id filter matches at the ACTIVITY level; one activity
                # can carry sibling events for other documents (a multi-file
                # share is one activity with one event per file). Mirror the
                # eventName sibling guard in _drive_external_sharing: only this
                # document's own events may feed owner/title/counts/listing.
                # An absent doc_id parameter cannot be attributed and is
                # skipped too (conservative: omission over contamination).
                if _scalar(p.get("doc_id")) != doc_id:
                    siblings_skipped += 1
                    continue
                name = ev.get("name") or "(unnamed)"
                counts[name] += 1
                # Newest-first stream: keep the first (most recent) non-empty value.
                owner = owner or _scalar(p.get("owner"))
                title = title or _scalar(p.get("doc_title"))
                if name in relevant:
                    if len(entries) < max_events:
                        entries.append(_doc_event_entry(it, ev, p))
                    else:
                        truncated = True
        out[c.domain] = {
            "owner": owner,
            "doc_title": title,
            "event_counts": dict(counts),
            "events": entries,
            "events_truncated": truncated,
            "sibling_events_skipped": siblings_skipped,
            "capped": capped,
        }
    return {"doc_id": doc_id, "window_days": days, "domains": out}


@mcp.tool()
def shared_drive_membership_changes(
    days: int = 180, domain: str | None = None, drive_name: str | None = None, max_pages: int = 5, max_events: int = 200
) -> dict:
    """Membership add/remove/role-change history across shared drives.

    Answers "who added this (external) member, and when" — the other half of
    triaging a shared-drive sharing finding (see ``drive_doc_activity``).
    Membership changes are low-volume, so a plain window scan of the single
    ``shared_drive_membership_change`` event works even over months.

    Each entry's ``drive`` is the shared drive's NAME as the audit log reports
    it (the event's ``owner`` parameter — not an id, not a user address);
    ``target_is_external`` classifies the affected member against the
    configured internal domains. The Reports API cannot filter by drive
    server-side, so ``drive_name`` is a client-side case-insensitive substring
    match on that name — it narrows the listing, not the scan. An event whose
    drive name is absent can neither match nor be ruled out; with
    ``drive_name`` set such events are excluded from ``total``/``entries`` but
    tallied in ``missing_drive_name`` so the drop is never silent (without
    ``drive_name`` they are listed normally with ``drive: null``).

    Args:
        days: How far back to scan (Reports API retains roughly 6 months).
        domain: Restrict to one configured domain/tenant (default: all).
        drive_name: Only list entries whose drive name contains this substring.
        max_pages: Reports page cap per domain; ``capped=true`` means more existed.
        max_events: Cap on listed entries (``total`` counts all matches).
    """
    try:
        clients, internal = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    start = _window(days * 24)
    needle = drive_name.strip().lower() if drive_name else None
    fetched = _fetch_drive_per_domain(
        picked, start=start, event_name="shared_drive_membership_change", max_pages=max_pages
    )
    out: dict = {}
    for c in picked:
        r = fetched[c.domain]
        if isinstance(r, Exception):
            out[c.domain] = {"error": str(r)}
            continue
        items, capped = r
        total = 0
        truncated = False
        missing_drive = 0
        entries: list[dict] = []
        for it in items:
            for ev in it.get("events", []):
                if ev.get("name") != "shared_drive_membership_change":
                    continue
                p = event_parameters(ev)
                drive = _scalar(p.get("owner"))
                if needle is not None:
                    if drive is None:
                        # Cannot match or rule out a nameless drive — surface
                        # the drop instead of silently undercounting.
                        missing_drive += 1
                        continue
                    if needle not in str(drive).lower():
                        continue
                total += 1
                if len(entries) >= max_events:
                    truncated = True
                    continue
                target = _scalar_lower(p.get("target_user"))
                entries.append(
                    {
                        **_entry(it, ev),
                        "drive": drive,
                        "target_user": target,
                        "target_is_external": is_external(target, internal) if target else None,
                        "membership_change_type": _scalar(p.get("membership_change_type")),
                        "new_value": p.get("new_value"),
                    }
                )
        out[c.domain] = {
            "total": total,
            "capped": capped,
            "events_truncated": truncated,
            "missing_drive_name": missing_drive,
            "entries": entries,
        }
    return {"window_days": days, "domains": out}


def _daily_brief_impl(hours: int, max_pages: int, samples: int) -> dict:
    """Compute the full daily_brief payload (shared by the sync tool and the job worker)."""
    try:
        clients, internal = _clients()
    except ConfigError as e:
        return {"error": str(e)}
    logins = _login_audit(clients, hours, include_failures=True, top=5)
    sharing = _drive_external_sharing(clients, internal, hours, max_pages=max_pages, samples=samples)
    summary: dict = {}
    for c in clients:
        d = c.domain
        la, ds = logins.get(d, {}), sharing.get(d, {})
        if "error" in la or "error" in ds:
            summary[d] = {"error": la.get("error") or ds.get("error")}
            continue
        summary[d] = {
            "account_disabled": len(la["account_disabled"]["entries"]),
            "suspicious_logins": len(la["suspicious_logins"]["entries"]),
            "login_failures": la.get("login_failures", {}).get("total", 0),
            "external_sharing_targets": ds["external_targets_total"],
            "risky_visibility_events": ds["risky_visibility_events"],
            "untargeted_external_transitions": ds["untargeted_external_transitions"],
            "capped": (
                la["account_disabled"]["capped"]
                or la["suspicious_logins"]["capped"]
                or la.get("login_failures", {}).get("capped", False)
                or ds["capped"]
            ),
        }
    return {
        "window_hours": hours,
        "summary": summary,
        "login_audit": logins,
        "drive_external_sharing": sharing,
    }


@mcp.tool()
def daily_brief(hours: int = 24, max_pages: int = 5, samples: int = 10) -> dict:
    """One-call security summary across all configured domains.

    Aggregates login_audit (account locks, suspicious logins) and
    drive_external_sharing (external grants, new link exposure, and
    ``untargeted_external_transitions`` — see that tool's docstring).
    ``max_pages`` / ``samples`` are passed through to the drive scan;
    ``max_pages`` defaults to the same page budget as the standalone tool,
    so both report the same counters for the same window (``samples``
    defaults lower here and only trims the example lists). Per-domain ``capped`` in the
    summary means at least one underlying scan was partial — treat that
    domain's counts as lower bounds (see ``capped_events`` in the drive
    section for which probes were cut short).

    Synchronous: on a large tenant this can exceed a client's ~60s tool-call
    timeout. If it does, use ``daily_brief_start`` + ``daily_brief_result``
    (same result, run in the background) or lower ``max_pages``.
    """
    return _daily_brief_impl(hours, max_pages, samples)


# --- background job + poll: daily_brief without hitting a client's ~60s tool timeout ---
# A large tenant's daily_brief can run past a gateway/client's per-call timeout, and
# clients do not extend it on progress notifications (see issue #10). So run the work in
# a background thread behind a fast "start" that returns a job id, and a "result" tool the
# model polls — no single call is long-lived. The registry is bounded (TTL-reaped + a hard
# cap) so a long-running single-user stdio server can't leak finished jobs.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL_SECONDS = 600  # retain a finished job this long AFTER it finishes (see _reap_jobs_locked)
_JOBS_MAX = 32  # hard cap on retained jobs (backstop; a single user has ~1 in flight)


def _reap_jobs_locked() -> None:
    """Drop finished jobs whose result has been retained past the TTL. Caller holds ``_JOBS_LOCK``.

    The TTL is measured from ``finished`` (completion), NOT ``created`` (start): a brief that
    itself ran longer than the TTL must still be retrievable for a full TTL window afterward —
    a long run is the whole reason ``daily_brief_start`` exists. Running jobs are never reaped.
    """
    now = time.monotonic()
    expired = [j for j, v in _JOBS.items() if v.get("finished") is not None and now - v["finished"] > _JOB_TTL_SECONDS]
    for jid in expired:
        del _JOBS[jid]


def _finish_job(job_id: str, payload: dict) -> None:
    """Record a job's terminal state + completion time (may have been reaped/evicted meanwhile)."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job.update(payload)
            job["finished"] = time.monotonic()  # the TTL retention window starts now, at completion


def _run_brief_job(job_id: str, hours: int, max_pages: int, samples: int) -> None:
    try:
        result = _daily_brief_impl(hours, max_pages, samples)
        _finish_job(job_id, {"status": "done", "result": result})
    except Exception as e:
        # Never let a worker thread die silently. Surface only the exception TYPE, not its
        # message: an unexpected error's text can embed internal paths/state (same reason
        # client.py omits it from GwsAuthError) and could be unbounded in size.
        _finish_job(job_id, {"status": "error", "error": type(e).__name__})


@mcp.tool()
def daily_brief_start(hours: int = 24, max_pages: int = 5, samples: int = 10) -> dict:
    """Start a daily_brief in the background; returns immediately with a ``job_id``.

    Use this instead of ``daily_brief`` when the synchronous call risks the client's ~60s
    tool-call timeout (large tenants). Args mirror ``daily_brief``. You MUST then poll
    ``daily_brief_result(job_id)`` every few seconds until ``status`` is ``done`` (the full
    daily_brief payload is under ``result``) or ``error``. On a config error returns
    ``{"error": ...}``; if too many jobs are already active returns
    ``{"status": "rejected", ...}``.
    """
    try:
        _clients()  # validate config + build the client cache up front, in this (fast) call
    except ConfigError as e:
        return {"error": str(e)}
    job_id = secrets.token_hex(8)
    with _JOBS_LOCK:
        _reap_jobs_locked()
        if len(_JOBS) >= _JOBS_MAX:
            return {"status": "rejected", "error": f"too many active brief jobs (>= {_JOBS_MAX}); retry shortly"}
        _JOBS[job_id] = {"status": "running", "created": time.monotonic()}
    thread = threading.Thread(
        target=_run_brief_job, args=(job_id, hours, max_pages, samples), name=f"daily_brief-{job_id}", daemon=True
    )
    try:
        thread.start()
    except RuntimeError as e:
        # e.g. the OS thread limit is hit: the worker never runs, so it would never finish and
        # never be reaped — drop the just-inserted "running" entry instead of leaking a zombie.
        with _JOBS_LOCK:
            _JOBS.pop(job_id, None)
        return {"status": "error", "error": type(e).__name__}
    return {"job_id": job_id, "status": "running", "poll_with": "daily_brief_result", "poll_after_seconds": 5}


@mcp.tool()
def daily_brief_result(job_id: str) -> dict:
    """Fetch a ``daily_brief_start`` job by id.

    ``status`` is ``running`` (keep polling), ``done`` (``result`` holds the full daily_brief
    payload), ``error`` (``error`` holds the exception type name — the message is omitted to
    avoid leaking internal detail), or ``unknown`` (bad/expired id).
    """
    with _JOBS_LOCK:
        # Reap here too, not only in start(): a client that only polls (or never starts
        # another job) must still have finished jobs — and their result payloads — bounded,
        # and an expired id must resolve to "unknown" as documented.
        _reap_jobs_locked()
        job = _JOBS.get(job_id)
        if job is None:
            return {"job_id": job_id, "status": "unknown"}
        out: dict = {"job_id": job_id, "status": job["status"]}
        if "result" in job:
            out["result"] = job["result"]
        if "error" in job:
            out["error"] = job["error"]
        return out


# --- diagnostic: does the client extend a tool call's timeout on progress? ---
# Registered only when GWSADM_ENABLE_TIMEOUT_PROBE is set, so it never appears in
# tools/list on a normal deployment. Defined unconditionally so tests can call it
# directly. See gwsadm issue #10: this exists to settle, end-to-end, whether
# emitting MCP progress notifications keeps a >60s call alive through the gateway
# before we commit to a job+poll rewrite of daily_brief.
_PROBE_STEP_SECONDS = 5
# Bound the diagnostic: tool inputs are LLM-driven (adversarial) even when the probe is
# enabled, so a caller can't tie the server up unboundedly. 600s is well above any gateway
# timeout the experiment probes (60/120/300s).
_PROBE_MAX_SECONDS = 600


async def timeout_probe(seconds: int = 90, emit_progress: bool = True, ctx: Context | None = None) -> dict:
    """Diagnostic: sleep ``seconds`` in ~5s steps, optionally emitting progress notifications.

    Gated behind GWSADM_ENABLE_TIMEOUT_PROBE (registered only when set). Tests whether emitting
    ``notifications/progress`` keeps a long (>60s) tool call alive through a gateway that would
    otherwise time out. ``ctx.report_progress`` is a no-op unless the client sent a ``progressToken``
    in the request ``_meta``, so ``progress_token_present`` reports whether one arrived end-to-end
    (if false, progress cannot possibly help regardless of ``emit_progress``).

    ``seconds`` is clamped to ``0..600``; ``requested_seconds`` echoes the raw input so a clamp is
    visible rather than surprising.
    """
    requested = seconds
    seconds = max(0, min(_PROBE_MAX_SECONDS, seconds))

    progress_token = None
    if ctx is not None and ctx.request_context.meta is not None:
        progress_token = ctx.request_context.meta.progressToken

    elapsed = 0
    steps = 0
    while elapsed < seconds:
        step = min(_PROBE_STEP_SECONDS, seconds - elapsed)
        # asyncio.sleep (not time.sleep) so the event loop can flush progress between steps.
        await asyncio.sleep(step)
        elapsed += step
        steps += 1
        if emit_progress and ctx is not None:
            await ctx.report_progress(progress=elapsed, total=seconds, message=f"timeout_probe: {elapsed}/{seconds}s")

    return {
        "requested_seconds": requested,
        "slept_seconds": elapsed,
        "steps": steps,
        "emit_progress": emit_progress,
        "progress_token_present": progress_token is not None,
    }


if os.environ.get("GWSADM_ENABLE_TIMEOUT_PROBE"):
    mcp.tool()(timeout_probe)
