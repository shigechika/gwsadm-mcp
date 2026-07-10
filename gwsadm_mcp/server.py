"""gwsadm-mcp MCP server — Google Workspace security audit (read-only).

Phase 1 tools:

- ``health_check``            — fleet-standard status/service/version + per-domain auth probe
- ``login_audit``             — Google-side auto-disabled accounts, suspicious logins, failure top-N
- ``drive_external_sharing``  — Drive ACL grants to external targets and new link/public exposure
- ``daily_brief``             — one-call summary of the above across all configured domains

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
    """
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
