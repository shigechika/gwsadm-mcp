"""gwsadm-mcp MCP server — Google Workspace security audit (read-only).

Phase 1 tools:

- ``health_check``            — fleet-standard status/service/version + per-domain auth probe
- ``login_audit``             — Google-side auto-disabled accounts, suspicious logins, failure top-N
- ``gmail_usage_report``      — daily Gmail send/receive counts per domain (Reports API
  ``customerUsageReports``; requires the separate ``admin.reports.usage.readonly`` DWD scope —
  see its docstring)
- ``suspended_accounts``      — current snapshot of suspended accounts (Directory API)
- ``get_user``                — one named account's state: suspended/archived/2SV/last login
  (Directory API; same ``admin.directory.user.readonly`` scope as ``suspended_accounts``)
- ``user_oauth_tokens``       — third-party OAuth app grants for one user (Directory API)
- ``gmail_message_trace``     — did a known Message-ID reach specific mailboxes, and where
  (Gmail API; requires the separate ``gmail.readonly`` DWD scope — see its docstring)
- ``dmarc_rua_summary``       — DMARC aggregate (RUA) report pass/fail summary per domain
  (Gmail API against the domain's configured RUA mailbox; shares ``gmail_message_trace``'s
  ``gmail.readonly`` DWD scope — see its docstring)
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
import email.utils
import functools
import inspect
import ipaddress
import os
import re
import secrets
import threading
import time

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError

from gwsadm_mcp import __version__, geo, sites
from gwsadm_mcp.client import DomainClient, GwsApiDisabledError, GwsAuthError, GwsError, event_parameters
from gwsadm_mcp.config import ConfigError, config_path, is_external, load_config


def _expose_errors(fn):
    """Wrap a tool so any exception reaches the model as a ToolError with its message.

    mcp 1.x returned the exception text for every failing tool. mcp 2.x hides it
    (the model sees only "Error executing tool <name>") unless a ToolError is raised.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    else:

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (ToolError, MCPError):
                raise
            except Exception as exc:
                raise ToolError(str(exc) or type(exc).__name__) from exc

    return wrapper


class _Server(MCPServer):
    """MCPServer whose tools report their exception messages (see _expose_errors)."""

    def tool(self, *args, **kwargs):
        register = super().tool(*args, **kwargs)

        def decorator(fn):
            register(_expose_errors(fn))
            return fn

        return decorator


mcp = _Server("gwsadm-mcp", version=__version__)

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


def _fan_out(jobs: dict) -> dict:
    """Run ``{key: zero-argument fetch}`` on one bounded worker pool.

    Returns ``{key: result | Exception}``: a ``GwsAuthError`` / ``GwsError``
    is captured per job (not raised) so each caller applies its own
    degradation policy -- a ``GwsAuthError`` fails its whole domain, a plain
    ``GwsError`` only that one probe. Running the probes serially would blow
    past a gateway's request timeout on a large tenant; the pool is bounded
    by ``GWSADM_MAX_WORKERS``. Every fan-out in this module goes through here
    so the worker bound and the error capture live in one place.
    """
    results: dict = {}
    if not jobs:
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(jobs))) as ex:
        futs = {ex.submit(fn): key for key, fn in jobs.items()}
        for fut in concurrent.futures.as_completed(futs):
            key = futs[fut]
            try:
                results[key] = fut.result()
            except (GwsAuthError, GwsError) as e:
                results[key] = e
    return results


def _parallel_fetch(tasks: list[tuple], start: datetime.datetime) -> dict:
    """Fetch ``(client, application, event_name, max_pages)`` tasks concurrently.

    Returns ``{(domain, application, event_name): (items, capped) | Exception}``
    (see ``_fan_out`` for the error policy). Pagination within a single fetch
    is still sequential (nextPageToken), so ordering within a probe is
    unchanged.
    """
    return _fan_out(
        {
            (c.domain, app, name): functools.partial(
                c.fetch_activities, app, start=start, event_name=name, max_pages=mp
            )
            for (c, app, name, mp) in tasks
        }
    )


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
    """Project one audit activity to ``{time, user, ip, event}``.

    ``user`` is normally the actor. On the Drive call sites it always is, and
    the account acted upon is reported separately as ``target_user``.

    The login call sites add one case where no actor exists to name.
    Google-initiated security events (``account_disabled_*``,
    ``suspicious_login``, ``gov_attack_warning``) carry
    ``actor = {"callerType": "KEY", "key": "Google"}`` — no email and no
    profileId, because Google itself acted — and name the affected account in
    the event's ``affected_email_address`` parameter instead. Reading the actor
    alone therefore anonymises exactly the entries that matter most: on
    2026-08-20 the disable event for a compromised mailbox was collected and
    reported with ``user: null``, so it could not be matched to the helpdesk
    ticket asking about that same mailbox. Drive events carry no
    ``affected_email_address``, so this fallback cannot fire there.
    """
    actor = item.get("actor", {})
    return {
        "time": item.get("id", {}).get("time"),
        # profileId is a numeric fallback: some restricted/system-initiated
        # events omit actor.email. affected_email_address comes last, so an
        # event that has an actor still names the actor -- it only resolves the
        # Google-initiated events, which have neither field. Ordering checked
        # against 30 days of this tenant's security events: every one was
        # callerType=KEY with no email and no profileId, so nothing observed is
        # shadowed by putting it last.
        "user": (
            actor.get("email")
            or actor.get("profileId")
            or _scalar(event_parameters(event).get("affected_email_address"))
        ),
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
    version, config, and domains (per-domain auth result plus ``gmail``:
    ok / api_disabled / no_grant / error, with ``gmail_detail`` on an
    unexpected error -- whether the per-user Gmail tools can work there; it
    does not affect ``status``), ``sites`` (the optional ``GWSADM_SITES_INI``
    table: configured / ranges / error) and ``geo`` (the optional
    ``GWSADM_IP2ASN`` dataset: configured / home_countries / age_days / error /
    warning); both are informational and do not affect ``status``. Lightweight: one 1-item login query and one
    ``users.getProfile`` per domain.
    """
    base = {
        "service": "gwsadm-mcp",
        "version": __version__,
        "config": config_path(),
        "sites": sites.load().status(),
        "geo": geo.load().status(),
    }
    try:
        clients, _ = _clients()
    except ConfigError as e:
        return {**base, "status": "error", "detail": str(e), "domains": []}
    # auth decides the overall status; gmail is a separately granted scope
    # (README: without it every other tool keeps working), so it is reported
    # per domain but does not degrade the service.
    results = [{**c.check(), **c.check_gmail()} for c in clients]
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

    Answers "did Google itself decide something was wrong with an account here,
    and with which account?" — the question a "my mail suddenly stopped working"
    ticket usually turns out to be. ``account_disabled_*`` is Google reporting
    that it locked an account (leaked password, hijacking, spamming);
    ``suspicious_login`` and ``gov_attack_warning`` are warnings without a lock.

    In both sections ``user`` is the account the event is ABOUT, not an actor
    who did something: Google raised these itself, so the actor is Google and
    the account is read from the event's ``affected_email_address``. Treat a
    hit as evidence about that account, and reach for ``get_user`` next for its
    current state.

    An ``account_disabled_spamming`` entry means Google observed outbound spam,
    which is a compromise finding, not a delivery problem — the account was
    almost certainly being used by someone else. The IdP upstream is a separate
    system and is NOT disabled by this: an account locked here can still
    authenticate there until it is disabled there too.

    Combine with a Directory suspended-users snapshot (Phase 2) for current
    state. Each section carries ``capped`` (window not fully scanned) — treat
    counts as lower bounds then.
    """
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    return {"window_hours": hours, "domains": _login_audit(picked, hours, include_failures, top)}


# Comma-separated app_name:param_name filter for customerUsageReports.get,
# restricting a call to just the Gmail traffic counters this tool reports --
# without it, one call pulls every application's counters (accounts, drive,
# calendar, ...), most of which nothing here uses.
GMAIL_USAGE_PARAMETERS = "gmail:num_emails_sent,gmail:num_emails_received"

# `days` drives a (domain x date) fan-out -- one blocking Reports API call per
# task, even though they now run concurrently (see _gmail_usage_report). An
# unbounded value could still queue an excessive number of tasks through the
# bounded worker pool and run for a long time. 90 covers a full quarter of
# daily reporting in one call, comfortably past any real use of this tool
# (compare MAX_TRACE_RECIPIENTS for the same style of caller-input bound).
MAX_USAGE_REPORT_DAYS = 90

# The Reports API's own date anchor for usage reports (UTC-8:00, i.e. Pacific
# Standard Time, year-round -- NOT PDT-adjusted). A plain fixed-offset
# timezone, not zoneinfo, since the API itself does not observe DST.
_REPORTS_USAGE_DATE_TZ = datetime.timezone(datetime.timedelta(hours=-8))


def _int_or_none(value) -> int | None:
    """Parse a Reports API parameter value (a JSON string, e.g. intValue) as int.

    Returns None on anything unparsable rather than raising -- one malformed
    or absent counter must not lose the rest of a day's report.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _recent_dates(days: int) -> list[str]:
    """Return ``days`` consecutive ``yyyy-mm-dd`` dates, most recent first,
    ending YESTERDAY in the Reports API's own date anchor (:data:`_REPORTS_USAGE_DATE_TZ`)
    -- not today, since the current day's usage data is not final until the
    day itself has ended in that timezone.
    """
    today = datetime.datetime.now(_REPORTS_USAGE_DATE_TZ).date()
    return [(today - datetime.timedelta(days=d)).isoformat() for d in range(1, days + 1)]


def _fetch_one_date_usage(c: DomainClient, date: str):
    """One (client, date) usage-report fetch. Runs in a worker thread -- see
    ``_gmail_usage_report``'s ``ThreadPoolExecutor`` fan-out."""
    return c.fetch_customer_usage(date=date, parameters=GMAIL_USAGE_PARAMETERS)


def _gmail_usage_report(clients: list[DomainClient], days: int) -> dict:
    dates = _recent_dates(days)
    # Fan every (domain x date) fetch out concurrently, same rationale as
    # _parallel_fetch/_fetch_drive_per_domain elsewhere in this file: this API
    # is inherently one blocking call per day, so running `len(clients) *
    # days` of them serially risks outrunning an MCP client's own tool-call
    # timeout on anything but a tiny window. Errors are captured per task
    # (not raised) so the aggregation below can apply its own domain-wide-vs-
    # per-date distinction after every fetch has already completed.
    tasks = [(c, date) for c in clients for date in dates]
    results: dict[tuple[str, str], tuple[list[dict], bool] | GwsError] = {}
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(tasks))) as ex:
            futs = {ex.submit(_fetch_one_date_usage, c, date): (c.domain, date) for c, date in tasks}
            for fut in concurrent.futures.as_completed(futs):
                key = futs[fut]
                try:
                    results[key] = fut.result()
                except (GwsAuthError, GwsError) as e:
                    results[key] = e

    out: dict = {}
    for c in clients:
        daily: list[dict] = []
        date_errors: list[dict] = []
        domain_error: str | None = None
        capped = False
        for date in dates:
            r = results[(c.domain, date)]
            if isinstance(r, GwsAuthError):
                # The whole domain lacks this scope -- identical for every
                # date, so one representative message is surfaced instead of
                # `days` duplicate entries under date_errors.
                domain_error = str(r)
                continue
            if isinstance(r, GwsError):
                # A single date's fetch failing for some other reason (e.g.
                # Google's processing for that day isn't finished yet -- a
                # known Reports API lag) is NOT domain-wide.
                date_errors.append({"date": date, "error": str(r)})
                continue
            reports, date_capped = r
            try:
                for rep in reports:
                    p = event_parameters(rep)
                    daily.append(
                        {
                            "date": rep.get("date") or date,
                            "num_emails_sent": _int_or_none(p.get("gmail:num_emails_sent")),
                            "num_emails_received": _int_or_none(p.get("gmail:num_emails_received")),
                        }
                    )
            except (AttributeError, TypeError) as e:
                # A malformed usageReports entry (not a plain dict, or a
                # parameters item that isn't one) must not crash the whole
                # tool call for every domain -- degrade just this one date.
                date_errors.append({"date": date, "error": f"malformed usage report entry: {e}"})
                continue
            capped = capped or date_capped
        if domain_error is not None:
            out[c.domain] = {"error": domain_error}
        else:
            out[c.domain] = {"daily": daily, "date_errors": date_errors, "capped": capped}
    return out


@mcp.tool()
def gmail_usage_report(days: int = 7, domain: str | None = None) -> dict:
    """Daily Gmail send/receive counts per domain (Admin SDK customerUsageReports).

    Answers "how much Gmail traffic did this domain send/receive on day X" --
    a customer-level daily counter, NOT a per-user or per-message breakdown
    (the Reports API has no such thing; ``login_audit``'s activity stream is
    the per-event alternative for that, at the cost of no volume total).

    Each day's fetch is independent: a domain missing the DWD scope reports
    one whole-domain ``error`` (there is no point retrying `days` times for
    an identical scope failure), but a single date's fetch failing for some
    other reason (Google's processing for that day not finished yet is a
    known lag on this API family; a transient error) only skips that one
    date, recorded in ``date_errors`` -- the rest of the window still comes
    back. The per-domain result also carries ``capped`` -- true if ANY
    date's fetch hit the (rare, since a single day's customer report is
    normally one record) pagination limit -- so a truncated day's counters
    are never mistaken for the complete picture.

    Requires the ``admin.reports.usage.readonly`` DWD scope, granted PER
    SERVICE ACCOUNT CLIENT ID in the Admin console (Security > API controls >
    Domain-wide delegation) -- a DIFFERENT scope from
    ``admin.reports.audit.readonly`` (the one ``login_audit``,
    ``drive_external_sharing``, ``drive_doc_activity``,
    ``shared_drive_membership_changes`` and ``daily_brief`` use), even though
    both live under the same Admin SDK Reports API. Having one does not
    imply the other; grant this one separately.

    Read-only: only ``customerUsageReports().get()`` is issued, restricted to
    the two Gmail counters this tool reports via the API's own ``parameters``
    filter (:data:`GMAIL_USAGE_PARAMETERS`) rather than pulling every
    application's counters.

    Args:
        days: How many days back to report, ending YESTERDAY (not today --
            the current day's data is not final until it ends) in the
            Reports API's own UTC-8:00/Pacific-Standard-Time date anchor.
            Must be ``1..``:data:`MAX_USAGE_REPORT_DAYS` -- ``0``/negative
            would otherwise silently return a well-formed, error-free empty
            result indistinguishable from "queried correctly, zero Gmail
            traffic that window", and an unbounded value drives an unbounded
            (domain x date) fan-out (one blocking API call per task, even
            though they run concurrently).
        domain: Configured ``[domain.*]`` section to report on. Default: all
            configured domains.
    """
    if not (1 <= days <= MAX_USAGE_REPORT_DAYS):
        return {"error": f"days must be between 1 and {MAX_USAGE_REPORT_DAYS}, got {days}"}
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    return {"days": days, "domains": _gmail_usage_report(picked, days)}


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

    ``suspension_time`` and ``archival_time`` are CONDITIONAL, not unsupported:
    Google omits each on an account the state does not apply to, so ``None``
    there reads as "not in that state", never as "the API cannot say". Verified
    against a live tenant through this exact path (``projection="basic"``, the
    read-only directory scope): a genuinely suspended account came back carrying
    ``suspensionTime``, and the same response omitted ``archivalTime`` because
    that account was not archived. ``projection="basic"`` narrows CUSTOM schema
    fields only — the parameter's own enum wording — and leaves standard
    output-only fields like these two alone.
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
    That tool lists only accounts that ARE suspended, so it can never confirm
    that a given address is *not* suspended, and once that list exceeds its
    page cap absence stops being evidence either way — after spending far more
    API calls than this. ``suspended_accounts`` is for the domain-wide sweep it
    is actually named for.

    This directory is downstream of the identity provider, not the master. Read
    the answer as "what Google Workspace currently believes about this account"
    and compare it against the IdP's own record, which is authoritative for who
    the account is. A disagreement is usually drift on this side rather than a
    mistyped address — an account the IdP still authenticates can be suspended
    or archived here, and an address the IdP does not assert at all will simply
    come back ``found: false``.

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


# user_activity / ip_activity: the Reports API applications walked by default
# for one account's, or one source address's, timeline. ``gmail`` is absent on
# purpose: message-level Gmail activity is not served by the Reports API on
# every tenant (verified live: ``applicationName=gmail`` answers HTTP 400 on a
# tenant whose every other application works), and a caller whose tenant has
# it passes it explicitly. The list is an argument, not a fixed set, because
# the right applications depend on what the tenant uses.
ACTIVITY_APPLICATIONS = ("login", "token", "user_accounts", "drive", "groups", "calendar", "chat", "meet", "saml")
# An application name is a path segment of the request URL, so it is validated
# against a charset before use (same treatment as ``_DOC_ID_RE``: tool inputs
# are LLM-driven and must be treated as adversarial).
_APPLICATION_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
MAX_ACTIVITY_APPLICATIONS = 20

# Events that change an account's security posture, or mark it as under
# attack. ``flags`` surfaces these on top regardless of volume because they
# are what a compromise leaves behind once the session itself is gone: a
# second factor the attacker enrolled survives a password reset (observed
# live, 2026-10-16: ``2sv_enroll`` from the attacker's address fifteen
# minutes after the first SAML login, with no Drive activity at all), a
# recovery address captures the next reset, an outbound forwarding rule keeps
# leaking, an OAuth grant needs no further login. Names are the Reports API's
# own, from the ``login``, ``user_accounts`` and ``token`` applications.
POSTURE_EVENTS = frozenset(
    {
        "2sv_enroll",
        "2sv_disable",
        "passkey_enrolled",
        "passkey_removed",
        "titanium_unenroll",
        "password_edit",
        "recovery_email_edit",
        "recovery_phone_edit",
        "recovery_secret_qa_edit",
        "email_forwarding_out_of_domain",
        "risky_sensitive_action_allowed",
        "risky_sensitive_action_blocked",
        "authorize",
        *ACCOUNT_DISABLED_EVENTS,
        *SUSPICIOUS_LOGIN_EVENTS,
    }
)
# Event parameters worth carrying on a timeline row. Everything else the API
# attaches (dozens of bookkeeping fields on a Drive event) is dropped so a
# day's timeline stays readable; the application-level counts are unaffected.
_ACTIVITY_PARAMS = (
    "login_type",
    "is_suspicious",
    "is_second_factor",
    "login_challenge_method",
    "sensitive_action_name",
    "app_name",
    "client_id",
    "client_type",
    "scope",
    "email_forwarding_destination_address",
    "doc_id",
    "doc_title",
    "doc_type",
    "owner",
    "visibility",
    "old_visibility",
    "target_user",
    "target_domain",
    "new_value",
)
# Drive events that belong on the timeline: ACL changes and the document
# lifecycle. The access noise (view/edit/download/print/preview) is counted
# per event name instead -- a hot afternoon of reading produces hundreds of
# rows that would drown the one share or delete that matters.
DRIVE_TIMELINE_EVENTS = frozenset(DRIVE_ACL_EVENTS) | frozenset(DOC_LIFECYCLE_EVENTS)


def _parse_applications(raw: str | None) -> list[str]:
    """Split a comma-separated application list, validating each name.

    ``None``/empty means the default set. Raises ``GwsError`` on a name that
    could not be a Reports API application (it would otherwise reach the
    request URL as a path segment) or on more than MAX_ACTIVITY_APPLICATIONS.
    """
    if raw is None or not raw.strip():
        return list(ACTIVITY_APPLICATIONS)
    apps: list[str] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if not name:
            continue
        if not _APPLICATION_RE.match(name):
            raise GwsError(f"'{name}' is not a Reports API application name")
        if name not in apps:
            apps.append(name)
    if not apps:
        return list(ACTIVITY_APPLICATIONS)
    if len(apps) > MAX_ACTIVITY_APPLICATIONS:
        raise GwsError(f"at most {MAX_ACTIVITY_APPLICATIONS} applications per call, got {len(apps)}")
    return apps


def _parse_ip(raw: str) -> str:
    """Normalise an IP literal, or raise ``GwsError``.

    The value becomes the ``actorIpAddress`` query parameter, so anything that
    is not an address is refused here rather than handed to the API as a
    filter that silently matches nothing. A zone-scoped IPv6 literal
    (``fe80::1%eth0``) is refused too: ``ipaddress`` accepts it, but the zone
    means nothing to the API and would turn every application's answer into
    an HTTP 400 instead of the input error promised here.
    """
    raw = raw.strip()
    if "%" in raw:
        raise GwsError(f"'{raw}' is not an IP address (zone id not allowed)")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as e:
        raise GwsError(f"'{raw}' is not an IP address") from e


# The Google-initiated verdicts -- ``account_disabled_*``, ``suspicious_*``,
# ``gov_attack_warning`` -- are NOT returned under the affected account's own
# ``userKey``: their actor is Google (``callerType=KEY``) and ``userKey``
# filters on the actor. Verified live, 2026-10-17: an account carrying an
# ``account_disabled_hijacked`` verdict three weeks earlier answered 146 login
# events under its userKey and not that one. ``user_activity`` therefore
# fetches these event names the way ``login_audit`` does (``userKey=all``, one
# probe per name) and keeps the events whose ``affected_email_address`` names
# the account -- the same fallback ``_entry`` applies -- under the synthetic
# application LOGIN_VERDICTS, so the reader can see they came by a different
# route than the account's own events.
VERDICT_EVENTS = ACCOUNT_DISABLED_EVENTS + SUSPICIOUS_LOGIN_EVENTS
VERDICT_MAX_PAGES = 2
LOGIN_VERDICTS = "login_verdicts"


def _application_jobs(
    picked: list[DomainClient],
    applications: list[str],
    *,
    start: datetime.datetime,
    max_pages: int,
    user_key: str = "all",
    actor_ip: str | None = None,
) -> dict:
    """``{(domain, application): fetch}`` jobs for ``_fan_out``.

    One unfiltered-by-event probe per (domain × application), carrying the
    per-account / per-IP narrowing that ``_parallel_fetch``'s task tuple
    cannot. Every domain's applications go into the one pool the caller runs,
    so a slow or retrying domain does not hold up the others' results.
    """
    return {
        (c.domain, app): functools.partial(
            c.fetch_activities, app, start=start, max_pages=max_pages, user_key=user_key, actor_ip=actor_ip
        )
        for c in picked
        for app in applications
    }


def _fetch_per_application(
    picked: list[DomainClient],
    applications: list[str],
    *,
    start: datetime.datetime,
    max_pages: int,
    user_key: str = "all",
    actor_ip: str | None = None,
) -> dict:
    """Run ``_application_jobs`` and regroup as ``{domain: {application: (items,
    capped) | Exception}}`` so the caller applies its own degradation: a
    ``GwsAuthError`` means that domain is unusable, a plain ``GwsError`` only
    that one application (e.g. a tenant without ``gmail`` activity)."""
    results: dict = {c.domain: {} for c in picked}
    jobs = _application_jobs(
        picked, applications, start=start, max_pages=max_pages, user_key=user_key, actor_ip=actor_ip
    )
    for (dom, app), r in _fan_out(jobs).items():
        results[dom][app] = r
    return results


def _verdicts_for(username: str, results: dict) -> tuple[tuple[list[dict], bool], dict]:
    """Keep, from per-name ``userKey=all`` verdict fetches, the events about one account.

    ``results`` is ``{event_name: (items, capped) | Exception}``. Returns the
    kept ``(items, capped)`` -- each item trimmed to the events naming the
    account -- and ``{event_name: error}`` for the names whose probe failed
    (partial coverage, reported by the caller). A ``GwsAuthError`` is raised:
    that is the domain failing, not one probe.
    """
    wanted = username.lower()
    items: list[dict] = []
    capped = False
    errors: dict = {}
    for name, r in results.items():
        if isinstance(r, GwsAuthError):
            raise r
        if isinstance(r, GwsError):
            errors[name] = str(r)
            continue
        got, c = r
        capped = capped or c
        for it in got:
            keep = [ev for ev in it.get("events", []) or [] if str(_entry(it, ev)["user"] or "").lower() == wanted]
            if keep:
                items.append({**it, "events": keep})
    return (items, capped), errors


def _activity_row(application: str, item: dict, event: dict, p: dict) -> dict:
    row = {**_entry(item, event), "application": application}
    params = {k: p[k] for k in _ACTIVITY_PARAMS if k in p}
    if params:
        row["params"] = params
    return row


def _is_posture_event(name: str | None, p: dict) -> bool:
    if name in POSTURE_EVENTS:
        return True
    # A successful login Google itself judged suspicious is a flag even
    # though the event name is the everyday one.
    return name == "login_success" and str(_scalar(p.get("is_suspicious"))).lower() == "true"


def _collect_activity(fetched: dict, applications: list[str], *, want_timeline: bool = True) -> dict:
    """Merge per-application fetch results into one newest-first picture.

    Returns the per-application accounting, the merged ``timeline`` (Drive
    access noise excluded, see DRIVE_TIMELINE_EVENTS), the posture ``flags``,
    and the distinct source ``ips`` / acting ``accounts`` with first/last
    seen. ``want_timeline=False`` skips building the timeline and the ips
    bucket for a caller that reports neither (``ip_activity``), since a
    spraying address can carry thousands of rows per domain. Raises the
    ``GwsAuthError`` of any application: that is a domain failure, not a
    per-application one. ``fetched`` must hold every application asked for
    -- a missing one is a bug upstream, not an empty, fully-covered window.
    """
    apps: dict = {}
    timeline: list[dict] = []
    flags: list[dict] = []
    seen_flags: set = set()
    ips: dict = {}
    accounts: dict = {}
    capped = False
    for app in applications:
        r = fetched[app]
        if isinstance(r, GwsAuthError):
            raise r
        if isinstance(r, GwsError):
            apps[app] = {"error": str(r)}
            # A failed probe is a window never scanned: partial coverage,
            # reported the same way an over-budget one is (see login_audit's
            # event_errors), so a caller never reads it as "nothing there".
            capped = True
            continue
        items, app_capped = r
        capped = capped or app_capped
        counts: collections.Counter = collections.Counter()
        for item in items:
            for event in item.get("events", []) or []:
                name = event.get("name")
                counts[name] += 1
                p = event_parameters(event)
                row = _activity_row(app, item, event, p)
                if want_timeline and (app != "drive" or name in DRIVE_TIMELINE_EVENTS):
                    timeline.append(row)
                if _is_posture_event(name, p):
                    # The same posture event can be delivered under two
                    # applications (2sv_enroll appears in both login and
                    # user_accounts, with or without the login-side
                    # parameters); one flag per occurrence, keyed on what
                    # identifies the occurrence rather than on which route
                    # delivered it. An OAuth grant is identified by its
                    # client as well, so two authorizations at the same
                    # instant for different clients both survive.
                    ident = _scalar(p.get("client_id")) if name == "authorize" else None
                    key = (row["time"], name, row["ip"], row["user"], ident)
                    if key not in seen_flags:
                        seen_flags.add(key)
                        flags.append(row)
                buckets = ((accounts, row["user"]),)
                if want_timeline:
                    buckets += ((ips, row["ip"]),)
                for bucket, k in buckets:
                    if not k:
                        continue
                    agg = bucket.setdefault(
                        k, {"count": 0, "first": row["time"], "last": row["time"], "applications": set()}
                    )
                    agg["count"] += 1
                    agg["applications"].add(app)
                    t = row["time"] or ""
                    if t and (agg["first"] is None or t < agg["first"]):
                        agg["first"] = t
                    if t and (agg["last"] is None or t > agg["last"]):
                        agg["last"] = t
        apps[app] = {"count": sum(counts.values()), "capped": app_capped, "events": dict(counts.most_common())}
    timeline.sort(key=lambda r: r["time"] or "", reverse=True)
    flags.sort(key=lambda r: r["time"] or "", reverse=True)

    def _finish(bucket: dict, label: str) -> list[dict]:
        rows = [{label: k, **v, "applications": sorted(v["applications"])} for k, v in bucket.items()]
        rows.sort(key=lambda r: (r["last"] or "", r["count"]), reverse=True)
        return rows

    return {
        "applications": apps,
        "timeline": timeline,
        "flags": flags,
        "ips": _finish(ips, "ip"),
        "accounts": _finish(accounts, "user"),
        "capped": capped,
    }


@mcp.tool()
def user_activity(
    username: str,
    hours: int = 24,
    applications: str | None = None,
    max_pages: int = 5,
    max_events: int = 200,
    domain: str | None = None,
) -> dict:
    """Everything ONE account did across Workspace in a window, newest first.

    The first question after an upstream identity provider reports an account
    as compromised: did the attacker get into Google, and what did they do
    there? ``login_audit`` cannot answer it — it is a domain-wide view of the
    events Google itself raised, so it shows neither one named account's
    logins nor the logins Google did not flag. This tool asks the Reports API
    for that one account (``userKey=<username>``, server-side) across several
    applications at once and merges the answers.

    Read ``flags`` first. It holds the events that change the account's
    security posture or mark it as under attack, regardless of how much
    ordinary activity surrounds them: a second factor enrolled or disabled
    (``2sv_enroll`` survives a password reset — it is the attacker's way back
    in), recovery email/phone changes, a password change, outbound mail
    forwarding to another domain, Google's own ``risky_sensitive_action_*``
    verdicts, a login Google marked ``is_suspicious``, and every OAuth
    ``authorize`` (client and scopes — note that a service account
    impersonating the user through domain-wide delegation, this server's own
    Gmail tools included, appears here too, as an ``authorize`` whose
    ``client_id`` is the service account's numeric id). Google's
    ``account_disabled_*`` / ``suspicious_login`` / ``gov_attack_warning``
    verdicts are flags too, but they are NOT served under the account's own
    ``userKey`` (their actor is Google), so they are fetched separately the
    way ``login_audit`` does and reported under the synthetic application
    ``login_verdicts`` — its ``event_errors`` names any verdict probe that
    failed. ``ips`` lists the distinct source addresses with first/last seen
    and which applications each touched — the input to ``ip_activity`` for
    the "did the same source reach other accounts" question. ``timeline`` is
    the merged event list (Drive read/edit/download noise is counted under
    ``applications.drive.events`` but kept off the timeline), cut at
    ``max_events`` with ``timeline_truncated`` saying so. Counts on
    ``applications``, ``ips`` and the timeline are raw deliveries: an event
    the API delivers under two applications counts twice there and once in
    ``flags``.

    Coverage is explicit: ``window.start`` is the time actually asked for,
    each application reports its own ``capped`` (more pages existed) or
    ``error`` (that application failed — the others still answer), and
    ``capped`` at the top is their union, a failed application included.
    Reports data for the current day can lag by hours, so an empty window
    right after an incident is "not visible yet", not "nothing happened". A
    missing DWD scope or a rejected credential is a whole-call
    ``{"error": ...}``.

    Read-only (Reports API ``activities().list`` only, the same
    ``admin.reports.audit.readonly`` DWD scope as ``login_audit``).

    Args:
        username: Exact user email, passed through as the Reports API
            ``userKey`` (primary or alias address both work on Google's side).
        hours: Window length ending now.
        applications: Comma-separated Reports API application names to walk.
            Default: login, token, user_accounts, drive, groups, calendar,
            chat, meet, saml. ``gmail`` is deliberately not in the default —
            not every tenant has it — pass it explicitly where it exists.
        max_pages: Page budget per application (1000 events per page). The
            verdict probes use their own small budget (VERDICT_MAX_PAGES).
        max_events: Timeline rows returned (newest first); flags, ips and
            counts are computed over everything fetched regardless.
        domain: Configured ``[domain.*]`` section to route the lookup
            through. Default: resolved from the username's suffix.
    """
    username = username.strip()
    try:
        suffix = _domain_of(username)
        apps = _parse_applications(applications)
        clients, _ = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"username": username, "error": str(e)}
    return _user_activity_impl(picked[0], username, hours=hours, apps=apps, max_pages=max_pages, max_events=max_events)


def _user_activity_impl(
    c: DomainClient, username: str, *, hours: int, apps: list[str], max_pages: int, max_events: int
) -> dict:
    """``user_activity`` for a resolved client; shared with ``compromise_sweep``."""
    start = _window(hours)
    # One pool for the account's own applications and the verdict probes.
    jobs = _application_jobs([c], apps, start=start, max_pages=max_pages, user_key=username)
    jobs.update(
        {
            ("verdict", name): functools.partial(
                c.fetch_activities, "login", start=start, event_name=name, max_pages=VERDICT_MAX_PAGES
            )
            for name in VERDICT_EVENTS
        }
    )
    res = _fan_out(jobs)
    fetched = {app: res[(c.domain, app)] for app in apps}
    try:
        fetched[LOGIN_VERDICTS], verdict_errors = _verdicts_for(
            username, {name: res[("verdict", name)] for name in VERDICT_EVENTS}
        )
        got = _collect_activity(fetched, [*apps, LOGIN_VERDICTS])
    except GwsAuthError as e:
        return {"domain": c.domain, "username": username, "error": str(e)}
    if verdict_errors:
        got["applications"][LOGIN_VERDICTS]["event_errors"] = verdict_errors
        got["capped"] = True
    timeline = got["timeline"]
    return {
        "domain": c.domain,
        "username": username,
        "window": {"hours": hours, "start": start.isoformat(timespec="seconds")},
        "applications": got["applications"],
        "flags": got["flags"],
        "ips": got["ips"],
        "timeline": timeline[:max_events],
        "timeline_truncated": len(timeline) > max_events,
        "capped": got["capped"],
    }


@mcp.tool()
def ip_activity(
    ip: str,
    hours: int = 24,
    applications: str | None = None,
    max_pages: int = 5,
    top: int = 50,
    domain: str | None = None,
) -> dict:
    """Every account ONE source address acted as, across applications and domains.

    The follow-through after ``user_activity`` names an attacker's address:
    did the same source get into other accounts? The Reports API filters on
    ``actorIpAddress`` server-side, so this is one probe per
    (domain × application) over the matching events only, not a scan of the
    whole tenant's log — and every domain's probes run in one pool, so a
    slow domain does not delay another's answer. Per domain it returns the
    acting ``accounts`` (count, first/last seen, which applications) ordered
    by most recent, the posture ``flags`` the address triggered (same
    definition as ``user_activity``; Google's own verdicts are included here
    when they carry the address, since ``userKey=all`` sees them), and
    per-application accounting. Failed logins from the address appear under
    ``applications.login.events`` as ``login_failure`` — a spray from this
    address shows there before it ever succeeds.

    Coverage reads as in ``user_activity``: ``window.start``, per-application
    ``capped`` / ``error`` (and the union ``capped``, a failed application
    included), and a per-domain ``error`` when that domain's credential is
    rejected (the other domains still answer). A quiet answer for a
    current-day window can be data lag rather than absence.

    Read-only (Reports API ``activities().list`` only, the
    ``admin.reports.audit.readonly`` DWD scope).

    Args:
        ip: The source address, IPv4 or IPv6 literal (no zone id). Validated
            before use.
        hours: Window length ending now.
        applications: Comma-separated application names; default as in
            ``user_activity``.
        max_pages: Page budget per (domain × application).
        top: Accounts returned per domain, most recently seen first;
            ``accounts_total`` says how many there were.
        domain: Restrict to one configured ``[domain.*]`` section. Default:
            every configured domain, since an address is not tied to one.
    """
    try:
        ip = _parse_ip(ip)
        apps = _parse_applications(applications)
        clients, _ = _clients()
        picked = _select(clients, domain)
    except (ConfigError, GwsError) as e:
        return {"ip": ip, "error": str(e)}
    return _ip_activity_impl(picked, ip, hours=hours, apps=apps, max_pages=max_pages, top=top)


def _ip_activity_impl(
    picked: list[DomainClient], ip: str, *, hours: int, apps: list[str], max_pages: int, top: int
) -> dict:
    """``ip_activity`` for resolved clients and a validated address; shared with ``compromise_sweep``."""
    start = _window(hours)
    # Every (domain × application) probe at once, then aggregate per domain.
    fetched = _fetch_per_application(picked, apps, start=start, max_pages=max_pages, actor_ip=ip)
    out: dict = {}
    for c in picked:
        try:
            got = _collect_activity(fetched[c.domain], apps, want_timeline=False)
        except GwsAuthError as e:
            out[c.domain] = {"error": str(e)}
            continue
        out[c.domain] = {
            "applications": got["applications"],
            "accounts_total": len(got["accounts"]),
            "accounts": got["accounts"][:top],
            "flags": got["flags"],
            "capped": got["capped"],
        }
    return {
        "ip": ip,
        "window": {"hours": hours, "start": start.isoformat(timespec="seconds")},
        "domains": out,
    }


# compromise_sweep: which of a user's OAuth grants can read or act on content
# (mail, Drive, contacts, admin) -- the grants worth naming after a compromise,
# as opposed to the sign-in-only ones (openid / userinfo) that every
# "Sign in with Google" button leaves behind.
_RISKY_SCOPE_RE = re.compile(r"mail\.google\.com|/auth/gmail\.|/auth/drive|/auth/contacts|/auth/admin\.")
# Source addresses swept for other accounts when the caller gives none: those
# on the account's own flags, newest first, capped so a noisy account does not
# turn one call into dozens of cross-domain scans.
SWEEP_MAX_IPS = 5
SWEEP_IP_APPLICATIONS = ["login", "token", "user_accounts"]
SWEEP_IP_MAX_PAGES = 2
SWEEP_IP_TOP = 20
SWEEP_ACTIVITY_EVENTS = 50


def _parse_ips(raw: str | None) -> list[str]:
    """Comma-separated addresses, each validated by ``_parse_ip``, deduplicated."""
    out: list[str] = []
    for part in (raw or "").split(","):
        if part.strip():
            ip = _parse_ip(part)
            if ip not in out:
                out.append(ip)
    if len(out) > SWEEP_MAX_IPS:
        # Refused rather than silently truncated: an address not swept is an
        # address the caller believes was.
        raise GwsError(f"at most {SWEEP_MAX_IPS} addresses per sweep, got {len(out)}; split the call")
    return out


_EMPTY_GROUP_RE = re.compile(r"^\s*[^:,;]*:\s*;\s*$")


def _addresses(field: str | None) -> list[tuple[str, str]]:
    """Parse one recipient header into ``(name, addr)`` pairs without losing the valid ones.

    Strict ``getaddresses`` (the default since 3.13) answers ``[("", "")]``
    for the WHOLE header when any one address in it is malformed, which would
    drop every valid recipient next to it; on a header that strict parsing
    rejects, the lenient parser is used so the valid ones survive and only
    the malformed entry comes back empty (counted as unknown by the caller).
    An empty group (``undisclosed-recipients:;``, the usual To of a BCC-only
    send) names nobody and is not a recipient at all.
    """
    if not field or _EMPTY_GROUP_RE.match(field):
        return []
    pairs = email.utils.getaddresses([field])
    if pairs == [("", "")]:
        try:
            pairs = email.utils.getaddresses([field], strict=False)
        except TypeError:  # Python < 3.13 has no strict parameter (and no strict mode)
            pass
    return pairs


def _recipients(sampled: list[dict], internal: set[str]) -> dict:
    """Reduce sent-message envelopes to counts: recipients, their domains, external and unparseable ones."""
    domains: collections.Counter = collections.Counter()
    total = external = unknown = 0
    for m in sampled:
        # One header at a time, and only the ones present: in strict mode
        # (the default since 3.13) getaddresses() rejects a whole list as
        # [("", "")] when any element fails to parse -- observed on 3.14 for
        # an empty string -- so one malformed header must not blank the rest.
        for field in (m.get("to"), m.get("cc"), m.get("bcc")):
            for _name, addr in _addresses(field):
                total += 1
                if not addr or "@" not in addr:
                    # A recipient that could not be parsed is still a
                    # recipient: counted as unknown AND as external (the
                    # fail-safe is_external() applies to an unreadable
                    # address), never silently dropped.
                    unknown += 1
                    external += 1
                    continue
                domains[addr.rsplit("@", 1)[-1].lower()] += 1
                if is_external(addr, internal):
                    external += 1
    return {
        "recipients_total": total,
        "external_recipients": external,
        "unknown_recipients": unknown,
        "recipient_domains": dict(domains.most_common(20)),
    }


def _filter_entry(f: dict) -> dict:
    action = f.get("action") or {}
    added = action.get("addLabelIds") or []
    return {
        "id": f.get("id"),
        "criteria": f.get("criteria") or {},
        "forward": action.get("forward"),
        "deletes": "TRASH" in added,
        "spams": "SPAM" in added,
        "archives": "INBOX" in (action.get("removeLabelIds") or []),
    }


def _send_as_entry(a: dict) -> dict:
    return {
        "send_as_email": a.get("sendAsEmail"),
        "reply_to": a.get("replyToAddress") or None,
        "is_primary": a.get("isPrimary"),
        "is_default": a.get("isDefault"),
        "treat_as_alias": a.get("treatAsAlias"),
        "verification_status": a.get("verificationStatus"),
    }


def _gmail_section(
    c: DomainClient, username: str, *, start: datetime.datetime, max_sent: int, internal: set[str]
) -> dict:
    """The Gmail half of a sweep, with its outcome made explicit in ``kind``.

    ``ok`` -- every settings section and the sent summary were read;
    ``partial`` -- the mailbox is readable but one or more settings sections
    (``section_errors``) or the sent summary (``sent.error``) failed, so
    "nothing found" does not hold for those; ``api_disabled`` -- the Gmail
    API is off in the service account's project (Cloud console);
    ``no_grant`` -- no ``gmail.readonly`` DWD grant (Admin console);
    ``error`` -- the settings could not be read for another reason. The
    settings and the sent summary are read independently: a sent-mail
    failure never discards a forwarding rule already found.
    """
    try:
        settings = c.gmail_security_settings(username)
    except GwsApiDisabledError as e:
        return {"kind": "api_disabled", "error": str(e)}
    except GwsAuthError as e:
        return {"kind": "no_grant", "error": str(e)}
    except GwsError as e:
        return {"kind": "error", "error": str(e)}
    try:
        got = c.gmail_sent_summary(username, start=start, max_messages=max_sent)
        sent: dict = {
            "count": got["count"],
            "capped": got["capped"],
            "sampled": len(got["sampled"]),
            **_recipients(got["sampled"], internal),
        }
    except GwsError as e:  # GwsAuthError / GwsApiDisabledError included: the settings still stand
        sent = {"error": str(e)}
    section_errors = settings.get("section_errors") or {}
    auto = settings.get("auto_forwarding") or {}
    filters = [_filter_entry(f) for f in settings.get("filters") or []]
    send_as = [_send_as_entry(a) for a in settings.get("send_as") or []]
    return {
        "kind": "partial" if section_errors or "error" in sent else "ok",
        "auto_forwarding": {
            "enabled": auto.get("enabled"),
            "email": auto.get("emailAddress"),
            "disposition": auto.get("disposition"),
        },
        "forwarding_addresses": [
            {"email": a.get("forwardingEmail"), "verification_status": a.get("verificationStatus")}
            for a in settings.get("forwarding_addresses") or []
        ],
        # Only the filters that move mail out of sight: forward, delete, mark as spam, archive.
        "filters": [f for f in filters if f["forward"] or f["deletes"] or f["spams"] or f["archives"]],
        "filters_total": len(filters),
        "delegates": [
            {"email": d.get("delegateEmail"), "verification_status": d.get("verificationStatus")}
            for d in settings.get("delegates") or []
        ],
        # The primary address only when it carries a reply-to (a reply-to
        # hijack); every non-primary alias.
        "send_as": [a for a in send_as if not a["is_primary"] or a["reply_to"]],
        "section_errors": section_errors,
        "sent": sent,
    }


def _highlights(username: str, activity: dict, grants: dict, ips: list[dict], gmail: dict) -> list[dict]:
    """The facts a responder acts on, one line each, in the order they matter."""
    out: list[dict] = []
    if "error" in activity:
        out.append({"kind": "activity_unreadable", "detail": f"activity: {activity['error']}"})
    for f in activity.get("flags", []):
        ev = f.get("event")
        if ev in ("2sv_enroll", "2sv_disable", "passkey_enrolled", "passkey_removed", "titanium_unenroll"):
            out.append({"kind": "second_factor", "detail": f"{ev} at {f['time']} from {f.get('ip')}"})
        elif ev in ("recovery_email_edit", "recovery_phone_edit", "recovery_secret_qa_edit", "password_edit"):
            out.append({"kind": "credential_change", "detail": f"{ev} at {f['time']} from {f.get('ip')}"})
        elif ev == "email_forwarding_out_of_domain":
            dest = (f.get("params") or {}).get("email_forwarding_destination_address")
            out.append({"kind": "forwarding", "detail": f"{ev} at {f['time']} to {dest}"})
        elif ev in ("risky_sensitive_action_allowed", "risky_sensitive_action_blocked"):
            name = (f.get("params") or {}).get("sensitive_action_name")
            out.append({"kind": "sensitive_action", "detail": f"{ev} ({name}) at {f['time']} from {f.get('ip')}"})
        elif f.get("application") == LOGIN_VERDICTS:
            out.append({"kind": "google_verdict", "detail": f"{ev} at {f['time']}"})
    for t in grants.get("risky", []):
        out.append(
            {
                "kind": "oauth_grant",
                "detail": f"{t.get('display_text')} ({t.get('client_id')}): {', '.join(t.get('scopes', []))}",
            }
        )
    if gmail.get("kind") in ("ok", "partial"):
        auto = gmail["auto_forwarding"]
        if auto.get("enabled"):
            out.append(
                {
                    "kind": "forwarding",
                    "detail": f"auto-forwarding enabled to {auto.get('email')} ({auto.get('disposition')})",
                }
            )
        for a in gmail["forwarding_addresses"]:
            out.append(
                {"kind": "forwarding", "detail": f"forwarding address {a['email']} ({a['verification_status']})"}
            )
        for flt in gmail["filters"]:
            what = ", ".join(k for k in ("forward", "deletes", "spams", "archives") if flt[k])
            out.append(
                {
                    "kind": "filter",
                    "detail": f"filter {flt['id']}: {what}" + (f" -> {flt['forward']}" if flt["forward"] else ""),
                }
            )
        for d in gmail["delegates"]:
            out.append({"kind": "delegate", "detail": f"delegate {d['email']} ({d['verification_status']})"})
        for a in gmail["send_as"]:
            out.append(
                {
                    "kind": "send_as",
                    "detail": f"send-as {a['send_as_email']} reply-to {a['reply_to']} ({a['verification_status']})",
                }
            )
        sent = gmail["sent"]
        if sent.get("count"):
            out.append(
                {
                    "kind": "sent_mail",
                    "detail": f"{sent['count']} message(s) sent in the window"
                    + (" (more exist)" if sent["capped"] else "")
                    + f"; {sent['external_recipients']} external recipient(s) in the {sent['sampled']} sampled"
                    + (f", {sent['unknown_recipients']} unparseable" if sent.get("unknown_recipients") else ""),
                }
            )
        for section, err in gmail.get("section_errors", {}).items():
            out.append({"kind": "gmail_unreadable", "detail": f"gmail settings.{section} not read -- {err}"})
        if "error" in sent:
            out.append({"kind": "gmail_unreadable", "detail": f"gmail sent mail not read -- {sent['error']}"})
    else:
        out.append({"kind": "gmail_unreadable", "detail": f"gmail: {gmail.get('kind')} -- {gmail.get('error')}"})
    for entry in ips:
        others = entry.get("other_accounts") or []
        if others:
            out.append({"kind": "other_accounts_from_ip", "detail": f"{entry['ip']}: {len(others)} other account(s)"})
    return out


def _checklist(activity: dict, gmail: dict) -> list[str]:
    """What this tool cannot settle and a person still has to."""
    items = [
        "Remove any second factor the attacker enrolled (Admin console > user > Security): a password reset alone "
        "does not revoke it.",
        "Reset the password and sign the account out of every session (Admin console > user > Security).",
        "Review recovery email / phone in the Admin console; this tool does not read them.",
        "Revoke the OAuth grants listed under grants.risky that the owner does not recognise.",
    ]
    kind = gmail.get("kind")
    if kind in ("ok", "partial"):
        failed = list(gmail.get("section_errors", {}))
        if failed:
            items.append(
                "These Gmail settings could not be read here and must be checked in the Admin console by hand: "
                + ", ".join(failed)
                + "."
            )
        if "error" in gmail.get("sent", {}):
            items.append("Sent mail could not be listed here: use the Admin console's Email Log Search.")
        else:
            items.append(
                "Message content is never read here: use the Admin console's Email Log Search for what was sent."
            )
    else:
        items.append(
            "Gmail settings and sent mail could not be read here ("
            + str(kind)
            + "): check forwarding, filters, delegates and the Email Log Search in the Admin console by hand."
        )
    items.append("Drive: run drive_external_sharing for the window and look for this account as the actor.")
    if "error" in activity:
        items.append(
            "The account's activity could not be read here (Reports API): the flags, source addresses and "
            "the IP sweep from them are missing -- re-run once the audit grant works, or pass ips explicitly."
        )
    if activity.get("capped"):
        items.append("The activity window was not fully covered (capped): narrow hours or raise max_pages and re-run.")
    return items


@mcp.tool()
def compromise_sweep(
    username: str,
    hours: int = 24,
    ips: str | None = None,
    max_pages: int = 5,
    max_sent: int = 20,
    domain: str | None = None,
) -> dict:
    """The Google-side follow-through after ONE account is confirmed compromised, in one call.

    Four questions, each answered from its own source and reported in its own
    section so that a failure in one never hides the others:

    - ``activity``: what the account did (``user_activity`` for the window,
      flags first -- a ``2sv_enroll`` from the attacker is the item that
      survives a password reset). A Reports failure stays in this section
      as ``error``; the others are still attempted with their own grants.
    - ``state`` / ``grants``: what the account is now (``get_user``:
      suspended, 2SV enrolled, last login) and which OAuth grants can read or
      act on content (``grants.risky``: mail / Drive / contacts / admin
      scopes; sign-in-only grants are listed but not called out).
    - ``ips``: whether the same sources reached other accounts
      (``ip_activity`` across every configured domain for the addresses in
      ``ips``, or, when none are given, for the addresses on the account's
      own flags -- which include the attacker's, and also the owner's own
      when they authorized an app or re-authenticated -- capped at
      SWEEP_MAX_IPS, newest first). The swept account itself is excluded
      from ``other_accounts``; a shared egress address (a campus NAT, a
      gateway host that impersonates accounts) legitimately shows other
      accounts, so read ``other_accounts`` against where the address sits.
    - ``gmail``: the settings an attacker leaves behind to keep reading mail
      (auto-forwarding, forwarding addresses, filters that forward / delete /
      archive, delegates, send-as aliases and reply-to) plus what the mailbox
      sent in the window as counts and recipient domains -- never a subject
      or body. Its ``kind`` says whether it could be read at all: ``ok``,
      ``partial`` (a settings section or the sent summary failed --
      ``section_errors`` / ``sent.error`` say which; the rest stands),
      ``api_disabled`` (the Gmail API is off in the service account's own
      Cloud project), ``no_grant`` (no ``gmail.readonly`` DWD grant) or
      ``error``. A failure is reported as such, never as "nothing found".

    ``highlights`` lists the facts a responder acts on, one line each, and
    ``checklist`` what remains to do or verify by hand (second-factor
    removal, session sign-out, recovery contacts, message content). Nothing
    here changes the account; the identity provider's side of the incident
    (and any other SaaS) stays with the caller.

    Read-only: Reports API ``activities().list``, Directory ``users().get``
    and ``tokens().list``, and Gmail ``settings.*`` reads plus
    ``messages().list`` / ``messages().get(format="metadata")`` with the
    To / Cc / Bcc / Date headers only.

    Args:
        username: Exact user email of the compromised account.
        hours: Window length ending now, for activity, the IP sweep and sent
            mail.
        ips: Comma-separated attacker addresses to sweep, at most
            SWEEP_MAX_IPS (more is refused, not truncated). Default: the
            addresses on the account's own flags, newest first, same cap.
        max_pages: Page budget per application for the account's activity
            (the IP sweep uses its own small budget).
        max_sent: Sent messages whose envelope is fetched, concurrently
            (the count covers everything listed).
        domain: Configured ``[domain.*]`` section for the account. Default:
            resolved from the username's suffix. The IP sweep always covers
            every configured domain.
    """
    username = username.strip()
    try:
        suffix = _domain_of(username)
        given_ips = _parse_ips(ips)
        clients, internal = _clients()
        picked = _select(clients, domain if domain is not None else suffix)
    except (ConfigError, GwsError) as e:
        return {"username": username, "error": str(e)}
    c = picked[0]
    start = _window(hours)
    # The four sources at once: they are independent, each with its own
    # grant, and serially they would not fit a client's tool-call budget.
    # Each one answers with a dict (errors inside it) or, for the two raw
    # Directory reads, raises a GwsError that _fan_out captures.
    res = _fan_out(
        {
            "activity": functools.partial(
                _user_activity_impl,
                c,
                username,
                hours=hours,
                apps=list(ACTIVITY_APPLICATIONS),
                max_pages=max_pages,
                max_events=SWEEP_ACTIVITY_EVENTS,
            ),
            "user": functools.partial(c.get_user, username),
            "tokens": functools.partial(c.list_user_oauth_tokens, username),
            "gmail": functools.partial(_gmail_section, c, username, start=start, max_sent=max_sent, internal=internal),
        }
    )
    # A Reports failure stays inside ``activity``: the Directory and Gmail
    # sections use their own grants and were attempted regardless.
    activity = res["activity"]
    activity_ok = "error" not in activity
    gmail = res["gmail"]

    user = res["user"]
    if isinstance(user, GwsError):
        state: dict = {"error": str(user)}
    else:
        state = {"found": user is not None}
        if user is not None:
            entry = _user_entry(user)
            state.update(
                {
                    k: entry[k]
                    for k in (
                        "email",
                        "suspended",
                        "suspension_reason",
                        "suspension_time",
                        "last_login",
                        "is_enrolled_in_2sv",
                        "is_enforced_in_2sv",
                        "change_password_at_next_login",
                    )
                }
            )

    tokens = res["tokens"]
    if isinstance(tokens, GwsError):
        grants: dict = {"error": str(tokens)}
    else:
        entries = [_token_entry(t) for t in tokens]
        grants = {
            "count": len(entries),
            "risky": [t for t in entries if any(_RISKY_SCOPE_RE.search(sc or "") for sc in t.get("scopes", []))],
            "tokens": entries,
        }

    flagged = {f.get("ip") for f in activity.get("flags", [])} if activity_ok else set()
    sweep_ips = given_ips or [r["ip"] for r in activity.get("ips", []) if r["ip"] in flagged][:SWEEP_MAX_IPS]
    # The account as typed AND its canonical primary address: an alias is a
    # valid lookup key, but the Reports actor is always the primary.
    me = {username.lower(), str(state.get("email") or "").lower()} - {""}
    swept = _fan_out(
        {
            ip: functools.partial(
                _ip_activity_impl,
                clients,
                ip,
                hours=hours,
                apps=SWEEP_IP_APPLICATIONS,
                max_pages=SWEEP_IP_MAX_PAGES,
                top=SWEEP_IP_TOP,
            )
            for ip in sweep_ips
        }
    )
    ip_results: list[dict] = []
    for ip in sweep_ips:
        got = swept[ip]
        others: list[dict] = []
        errors: dict = {}
        capped = False
        for dom, d in got["domains"].items():
            if "error" in d:
                errors[dom] = d["error"]
                capped = True  # a domain never scanned is partial coverage
                continue
            capped = capped or d["capped"]
            for a in d["accounts"]:
                if str(a["user"]).lower() not in me:
                    others.append({"domain": dom, **a})
        ip_results.append({"ip": ip, "other_accounts": others, "capped": capped, "domain_errors": errors})

    return {
        "domain": c.domain,
        "username": username,
        "window": activity.get("window") or {"hours": hours, "start": start.isoformat(timespec="seconds")},
        "highlights": _highlights(username, activity, grants, ip_results, gmail),
        "activity": activity,
        "state": state,
        "grants": grants,
        "ips": ip_results,
        "gmail": gmail,
        "checklist": _checklist(activity, gmail),
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


# Reject-candidate IPs surfaced individually; the rest are folded into the
# per-domain totals only. Keeps a report from listing thousands of low-volume
# scanner/spoof source IPs -- the ones worth a human looking at are the
# high-count ones.
DMARC_TOP_IPS_DEFAULT = 15


def _aggregate_dmarc_rua(records: list[dict], top: int) -> dict:
    """Aggregate raw DMARC records into a per-policy-domain pass/fail summary.

    A record is a DMARC PASS when EITHER ``dkim`` or ``spf`` (the aligned
    ``policy_evaluated`` values, not the raw auth result) reads "pass" --
    counting any non-"pass" dkim as a failure regardless of spf overcounts
    dramatically, since a lot of legitimate mail passes DMARC via SPF
    alignment alone with DKIM unaligned or absent. A reject candidate is
    ``disposition`` already being ``"quarantine"`` or ``"reject"`` (RFC 7489's
    other two enforcement dispositions besides ``"none"``), OR both dkim and
    spf failing; anything else counts as pass. This mirrors the fix applied
    to an ad-hoc script that miscounted using the naive "dkim != pass" rule
    on 2026-09-01.

    Returns one entry per ``policy_domain`` seen across the input records:
    ``{pass, quarantined, rejected, undisposed_fail, reject_candidate_ips}``.
    ``quarantined``/``rejected`` are records a tenant's OWN CURRENT policy is
    already enforcing (relevant on a tenant already running `p=quarantine` or
    `p=reject`); ``undisposed_fail`` is a failing record `disposition="none"`
    let through -- what moving to a stricter policy would newly start
    blocking. Conflating ``rejected`` into ``undisposed_fail`` would misreport
    already-enforced blocking as still-pending. ``reject_candidate_ips`` is
    the top-``top`` source IPs among ALL reject candidates (by count), each
    with its own count, dispositions seen, and header_from values seen
    (multiple header_from values under one source IP usually means it also
    sends subdomain mail, whose true disposition depends on that
    subdomain's OWN ``sp=`` policy, not the parent domain's ``p=``).
    """
    per_domain: dict[str, dict] = {}
    reject_agg: dict[tuple[str, str], dict] = {}
    for r in records:
        pd = r["policy_domain"] or "(unknown)"
        bucket = per_domain.setdefault(pd, {"pass": 0, "quarantined": 0, "rejected": 0, "undisposed_fail": 0})
        disposition = r["disposition"]
        is_reject_candidate = disposition in ("quarantine", "reject") or (r["dkim"] != "pass" and r["spf"] != "pass")
        if disposition in ("quarantine", "reject"):
            bucket["quarantined" if disposition == "quarantine" else "rejected"] += r["count"]
        elif is_reject_candidate:
            bucket["undisposed_fail"] += r["count"]
        else:
            bucket["pass"] += r["count"]
        if is_reject_candidate:
            key = (pd, r["source_ip"])
            agg = reject_agg.setdefault(key, {"count": 0, "dispositions": set(), "header_from": set()})
            agg["count"] += r["count"]
            agg["dispositions"].add(r["disposition"] or "none")
            if r["header_from"]:
                agg["header_from"].add(r["header_from"])

    top_by_domain: dict[str, list[dict]] = {pd: [] for pd in per_domain}
    for (pd, ip), agg in sorted(reject_agg.items(), key=lambda kv: -kv[1]["count"]):
        bucket = top_by_domain.setdefault(pd, [])
        if len(bucket) < top:
            bucket.append(
                {
                    "source_ip": ip,
                    "count": agg["count"],
                    "dispositions": sorted(agg["dispositions"]),
                    "header_from": sorted(agg["header_from"]),
                }
            )
    return {pd: {**bucket, "reject_candidate_ips": top_by_domain.get(pd, [])} for pd, bucket in per_domain.items()}


def _dmarc_rua_report(
    clients: list[DomainClient], hours: int, mailbox: str | None, recipient: str | None, max_pages: int, top: int
) -> dict:
    start = _window(hours)
    out: dict = {}
    runnable: list[DomainClient] = []
    for c in clients:
        # A domain whose rua= lands in another domain's mailbox has nothing of
        # its own to read (DWD cannot impersonate a group/alias); its reports
        # still appear under that other domain's entry, keyed by the policy
        # domain each report names. An explicit mailbox override re-enables
        # the read for an ad-hoc check.
        if mailbox is None and c.cfg.dmarc_rua_mailbox is None:
            out[c.domain] = {"skipped": "DMARC reading is disabled for this domain (dmarc_rua_mailbox = none)"}
            continue
        runnable.append(c)

    def _one(c: DomainClient):
        return c.fetch_dmarc_rua_records(start=start, mailbox=mailbox, recipient=recipient, max_pages=max_pages)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_max_workers(), len(runnable) or 1)) as ex:
        futs = {ex.submit(_one, c): c for c in runnable}
        for fut in concurrent.futures.as_completed(futs):
            c = futs[fut]
            try:
                records, capped, message_errors, used_mailbox, used_recipient = fut.result()
            except (GwsAuthError, GwsError) as e:
                out[c.domain] = {"error": str(e)}
                continue
            out[c.domain] = {
                "mailbox": used_mailbox,
                "recipient": used_recipient,
                "capped": capped,
                "message_errors": message_errors,
                "policy_domains": _aggregate_dmarc_rua(records, top),
            }
    return out


@mcp.tool()
def dmarc_rua_summary(
    hours: int = 72,
    domain: str | None = None,
    mailbox: str | None = None,
    recipient: str | None = None,
    max_pages: int = 10,
    top: int = DMARC_TOP_IPS_DEFAULT,
) -> dict:
    """Summarize DMARC aggregate (RUA) reports: pass/fail per domain, top reject-candidate IPs.

    Impersonates the domain's configured ``dmarc_rua_mailbox`` (a real user --
    domain-wide delegation cannot act as a group or alias; config default
    ``postmaster@<domain>``), searches it for mail addressed to
    ``dmarc_rua_recipient`` (the ``rua=mailto:`` address published in DNS,
    e.g. the ``postmaster+rua@`` plus-subaddress; default: same as the
    mailbox), reads the aggregate reports those messages carry, and answers "how much of this domain's mail volume is
    passing DMARC, and if we moved the policy to ``p=reject``, what would
    actually get blocked?"

    A record counts as PASS when either its aligned DKIM or SPF check reads
    "pass" (DMARC's own OR semantics) — NOT when both do. A record counts as
    a reject candidate when it is already quarantined or rejected (a tenant
    already running `p=quarantine`/`p=reject` enforces this today), or when
    BOTH checks fail with `disposition="none"` (what a stricter policy would
    newly start blocking); everything else is a pass. This distinction
    matters a lot in practice: a large share of legitimate mail (mailing-list
    forwards, some relays) passes DMARC via SPF alignment alone with DKIM
    unaligned, so counting on DKIM alone overstates the failure rate
    severalfold.

    ``reject_candidate_ips`` (the top ``top`` per domain by volume) is where
    to actually look before flipping a policy to ``p=reject``: a header_from
    that names a SUBDOMAIN of the audited domain is governed by that
    subdomain's own ``sp=`` policy, not the parent's ``p=``, so it is not
    necessarily what a `p=reject` change on the parent would affect.

    Requires the ``gmail.readonly`` DWD scope — the same one
    ``gmail_message_trace`` needs, granted PER SERVICE ACCOUNT CLIENT ID in
    the Admin console (Security > API controls > Domain-wide delegation),
    separately from the ``admin.directory.*`` / ``admin.reports.*`` scopes
    the rest of this server uses.

    Read-only: only ``messages().list``/``messages().get``/
    ``attachments().get`` against the one configured mailbox are issued —
    see ``DomainClient.fetch_dmarc_rua_records``.

    Args:
        hours: Lookback window. Default 72 (3 days): RUA reports typically
            arrive roughly daily per sending source, so a single day's
            window risks missing infrequent senders entirely.
        domain: Configured ``[domain.*]`` section to report on. Default: all
            configured domains.
        mailbox: Override the configured ``dmarc_rua_mailbox`` (the user to
            impersonate) for every selected domain. Set this only for an
            ad-hoc check against a different inbox than the one in config;
            unless ``recipient`` is also given, that inbox's own address is
            searched. Also re-enables a domain configured with
            ``dmarc_rua_mailbox = none`` for the duration of the call.
            Validated as an email-shaped address (rejected otherwise).
        recipient: Override the address searched for (``to:``) for every
            selected domain -- the ``rua=mailto:`` value in DNS when it is
            not the mailbox itself. Validated as an email-shaped address
            (rejected otherwise) before use, since it is interpolated into
            a Gmail search query.
        max_pages: Gmail ``messages().list`` pages (100 messages each) to
            walk per domain. ``capped=true`` in the result means more pages
            existed — a capped fetch UNDER-counts real report volume, not
            just a lower bound on some other total, since every matching
            message must be walked (there is no server-side aggregate to
            fall back on).
        top: How many reject-candidate source IPs to return per domain
            (highest volume first). The per-domain pass/quarantined/
            rejected/undisposed_fail totals themselves are never truncated.
    """
    try:
        clients, _ = _clients()
        picked = _select(clients, domain)
        # mailbox (impersonation subject) and recipient (interpolated directly
        # into a Gmail search query, "to:{recipient}"; mailbox doubles as the
        # recipient when no recipient is given) are adversarial input like any
        # other tool argument, so both are validated as email-shaped (reusing
        # _domain_of purely for its shape check) BEFORE use -- unvalidated
        # whitespace or a search operator smuggled in here could change the
        # query's meaning and scan unrelated messages.
        for arg in (mailbox, recipient):
            if arg is not None:
                _domain_of(arg)
    except (ConfigError, GwsError) as e:
        return {"error": str(e)}
    return {
        "window_hours": hours,
        "domains": _dmarc_rua_report(picked, hours, mailbox, recipient, max_pages, top),
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
    """Run one drive probe per domain concurrently (``_parallel_fetch``'s task
    tuple cannot carry a ``filters`` expression). Returns ``{domain: (items,
    capped) | Exception}`` so each caller applies its own per-domain
    degradation."""
    return _fan_out(
        {
            c.domain: functools.partial(
                c.fetch_activities, "drive", start=start, event_name=event_name, filters=filters, max_pages=max_pages
            )
            for c in picked
        }
    )


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


# What an account's owner (or whoever holds the session) changed about how the
# account is protected, recovered, or where its mail goes. A compromise that
# wants to outlive a password reset leaves exactly these behind (observed live,
# 2026-10-16: ``2sv_enroll`` from the attacker's address fifteen minutes after
# the first login). Each name is probed with ``eventName=`` under the one
# application that emits it, checked against the live Reports API (2026-10-18,
# two tenants): ``2sv_enroll`` and the other ``user_accounts`` events are also
# echoed under ``login`` with identical counts, so they are read from
# ``user_accounts`` only to avoid counting them twice; ``passkey_enrolled`` /
# ``passkey_removed`` exist under ``login`` only (a passkey the attacker adds
# survives a password reset like a second factor does). There is no
# ``2sv_change_phone`` event: both applications answer HTTP 400 for it.
ACCOUNT_CHANGE_PROBES = (
    ("user_accounts", "2sv_enroll"),
    ("user_accounts", "2sv_disable"),
    ("user_accounts", "titanium_unenroll"),
    ("user_accounts", "password_edit"),
    ("user_accounts", "recovery_email_edit"),
    ("user_accounts", "recovery_phone_edit"),
    ("user_accounts", "recovery_secret_qa_edit"),
    ("user_accounts", "email_forwarding_out_of_domain"),
    ("login", "passkey_enrolled"),
    ("login", "passkey_removed"),
)
ACCOUNT_CHANGES_LISTED = 50


def _account_changes(clients: list[DomainClient], hours: int, logins: dict, max_pages: int = 2) -> dict:
    """Account-protection changes across each domain, flagged when they look like a takeover.

    Every row carries where it came from: ``site`` / ``external`` from the
    ``GWSADM_SITES_INI`` table (``external`` is ``null`` without a table, never
    ``false``) and ``country`` / ``asn`` / ``as_name`` from the
    ``GWSADM_IP2ASN`` dataset. ``external`` alone is not a flag: most owners
    change these settings from home (measured live, 2026-10-18: 107 of 133
    changes in a week came from outside the sites table, 102 of those from the
    home country). A row is ``flagged`` for one or more ``flag_reasons``:

    - ``foreign``: registered country outside ``GWSADM_HOME_COUNTRIES``
      (5 of those 107 in the same week, the known attacker among them);
    - ``unknown_origin``: the dataset is configured but the row has no address,
      or its address is outside the sites table and the dataset cannot place
      it (including when the dataset itself is missing or unreadable; ``geo``
      then carries the error) -- an origin that cannot be placed is not
      treated as home;
    - ``after_suspicious_login``: the same user had a suspicious login (from
      ``logins``, the login audit of the same window) at or before the change.

    Flagged rows are listed first; at most ``ACCOUNT_CHANGES_LISTED`` rows are
    listed per domain, ``total`` counts all.

    ``suspicious_login_coverage`` says how far the last reason can be trusted:
    ``complete``, ``partial`` (the suspicious-login scan was capped or lost an
    event probe, so ``after_suspicious_login: false`` may be wrong) or
    ``unavailable`` (the login audit failed for the domain;
    ``after_suspicious_login`` is then ``null``). Anything but ``complete`` is
    ORed into ``capped``: the flagged count is a lower bound.
    """
    start = _window(hours)
    table = sites.load()
    geo_table = geo.load()
    fetched = _parallel_fetch(
        [(c, app, name, max_pages) for c in clients for app, name in ACCOUNT_CHANGE_PROBES], start
    )
    raw: dict = {}
    for c in clients:
        la = logins.get(c.domain, {})
        if "error" in la:
            coverage = "unavailable"
        else:
            sl = la.get("suspicious_logins") or {}
            coverage = "partial" if (sl.get("capped") or sl.get("event_errors")) else "complete"
        try:
            rows: list[dict] = []
            capped = coverage != "complete"
            errors: dict = {}
            for app, name in ACCOUNT_CHANGE_PROBES:
                r = fetched[(c.domain, app, name)]
                if isinstance(r, GwsAuthError):
                    raise r
                if isinstance(r, GwsError):
                    # one event type unscanned: the section is partial, not "nothing found"
                    errors[name] = str(r)
                    capped = True
                    continue
                items, part_capped = r
                capped = capped or part_capped
                for it in items:
                    for ev in it.get("events", []):
                        if ev.get("name") != name:
                            continue
                        row = _entry(it, ev)
                        if name == "email_forwarding_out_of_domain":
                            row["destination"] = _scalar(
                                event_parameters(ev).get("email_forwarding_destination_address")
                            )
                        site = table.classify(row.get("ip"))
                        row["site"] = site.code if site else None
                        row["external"] = (site is None) if table.networks else None
                        rows.append(row)
            raw[c.domain] = (rows, capped, errors, coverage, la)
        except (GwsAuthError, GwsError) as e:
            raw[c.domain] = e
    # One pass over the dataset for every domain's addresses outside the sites table.
    places = geo_table.lookup(
        r["ip"] for v in raw.values() if not isinstance(v, Exception) for r in v[0] if r.get("ip") and r["site"] is None
    )
    out: dict = {}
    for c in clients:
        v = raw[c.domain]
        if isinstance(v, Exception):
            out[c.domain] = {"error": str(v)}
            continue
        rows, capped, errors, coverage, la = v
        suspicious: dict = {}
        for e in (la.get("suspicious_logins") or {}).get("entries", []):
            u = (e.get("user") or "").lower()
            if u and e.get("time") and (u not in suspicious or e["time"] < suspicious[u]):
                suspicious[u] = e["time"]
        for row in rows:
            reasons: list[str] = []
            place = places.get(row.get("ip") or "") if row["site"] is None else None
            row["country"] = place["cc"] if place else None
            row["asn"] = place["asn"] if place else None
            row["as_name"] = place["name"] if place else None
            # Gated on "configured", not "usable": a dataset that is missing or unreadable must not
            # turn every unplaced origin into an unflagged one (fail-safe, as for is_external()).
            if geo_table.configured and row["site"] is None:
                if not row["country"]:
                    reasons.append("unknown_origin")
                elif geo_table.home and row["country"] not in geo_table.home:
                    reasons.append("foreign")
            if coverage == "unavailable":
                row["after_suspicious_login"] = None
            else:
                first = suspicious.get((row.get("user") or "").lower())
                row["after_suspicious_login"] = bool(first and row.get("time") and first <= row["time"])
                if row["after_suspicious_login"]:
                    reasons.append("after_suspicious_login")
            row["flag_reasons"] = reasons
            row["flagged"] = bool(reasons)
        rows.sort(key=lambda x: (not x["flagged"], x.get("time") or ""))
        dom = {
            "total": len(rows),
            "flagged": sum(1 for x in rows if x["flagged"]),
            "by_reason": dict(collections.Counter(r for x in rows for r in x["flag_reasons"])),
            "by_event": dict(collections.Counter(x["event"] for x in rows)),
            "entries": rows[:ACCOUNT_CHANGES_LISTED],
            "capped": capped,
            "suspicious_login_coverage": coverage,
            "sites": table.status(),
            "geo": geo_table.status(),
        }
        if errors:
            dom["event_errors"] = errors
        out[c.domain] = dom
    return out


def _daily_brief_impl(hours: int, max_pages: int, samples: int) -> dict:
    """Compute the full daily_brief payload (shared by the sync tool and the job worker)."""
    try:
        clients, internal = _clients()
    except ConfigError as e:
        return {"error": str(e)}
    logins = _login_audit(clients, hours, include_failures=True, top=5)
    changes = _account_changes(clients, hours, logins)
    sharing = _drive_external_sharing(clients, internal, hours, max_pages=max_pages, samples=samples)
    summary: dict = {}
    for c in clients:
        d = c.domain
        la, ds, ac = logins.get(d, {}), sharing.get(d, {}), changes.get(d, {})
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
            # None when the account-change scan failed for this domain (see account_changes[d].error).
            "account_changes": ac.get("total"),
            "account_changes_flagged": ac.get("flagged"),
            "capped": (
                la["account_disabled"]["capped"]
                or la["suspicious_logins"]["capped"]
                or la.get("login_failures", {}).get("capped", False)
                or ds["capped"]
                or ac.get("capped", False)
            ),
        }
    return {
        "window_hours": hours,
        "summary": summary,
        "login_audit": logins,
        "account_changes": changes,
        "drive_external_sharing": sharing,
    }


@mcp.tool()
def daily_brief(hours: int = 24, max_pages: int = 5, samples: int = 10) -> dict:
    """One-call security summary across all configured domains.

    Aggregates login_audit (account locks, suspicious logins),
    account-protection changes (``account_changes``: 2-Step Verification
    enrolled/disabled, passkeys added/removed, Advanced Protection turned off,
    password and recovery address/phone edits, mail forwarding out of the
    domain; each row says whether it came from outside the ``GWSADM_SITES_INI``
    table and from which country (``GWSADM_IP2ASN``), and is ``flagged`` with
    ``flag_reasons`` -- ``foreign`` (outside ``GWSADM_HOME_COUNTRIES``),
    ``unknown_origin``, ``after_suspicious_login`` -- flagged rows first, at
    most 50 listed, ``total`` counts all; ``suspicious_login_coverage`` says
    whether the last reason is complete) and
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
