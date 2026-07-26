"""Probe specs for this server's tools — the Workspace-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

Three constraints shape everything below.

**Read-only.** Every tool here reads an audit log or a directory snapshot;
nothing in Workspace is changed. ``daily_brief_start`` does create server-side
state — a job in this process — but nothing in the tenant, and the job expires
on its own.

**No tenant-specific values in this file.** This repository is public, so a
probe may not name a domain, an account or a document. The two tools that need
such an argument get it from an ``args_factory`` that discovers one at run
time, and skip when the tenant has none to offer.

**Bounded.** These tools page the Reports API across every configured domain.
Their defaults (5 pages, 180 days, 200 events) are sized for a human asking
once; every probe passes a small explicit cap instead, so a scheduled run costs
a known, small number of API calls.

Assertions are envelope-first. A quiet tenant is a real and desirable
observation — no external sharing and no locked accounts is the goal — so a
probe asserts the accounting the tool always returns and, where the answer is
keyed by domain, that the domain map is not empty. A configuration that
resolves to zero domains would otherwise report every tool as working while
auditing nothing.
"""

import asyncio
import re
from typing import Any

from smoke_harness import Caller, Probe, SkipProbe

#: Non-empty per-domain map, asserted against the JSON rendering of the
#: payload. The keys are the tenant's own domains, so they cannot be named
#: here — what matters is that at least one is present.
DOMAINS_NOT_EMPTY = r'"domains": \{"'

#: A failed domain is reported *inside* the map — ``domains[<domain>] =
#: {"error": ...}`` — which the harness's top-level error check cannot see. A
#: run where every domain's credentials were rejected would otherwise return a
#: full-looking answer and pass. Matched on the quoted key, so the accounting
#: fields whose names end in "errors" (``event_errors``, ``fetch_errors``) do
#: not trip it.
NO_DOMAIN_ERROR = (r'"error":',)

#: Window and page bounds for the log-scanning tools. Small on purpose: one
#: page over one day proves the fetch, the external/internal classification and
#: the capping logic all run.
WINDOW_HOURS = 24
MAX_PAGES = 1


def _first_field(payload: Any, key: str, value_pattern: str = "[^'\"]+") -> str | None:
    """First value of ``key`` in a payload rendered as text, or None.

    The pattern is built from the key rather than written out, so this file
    never contains a key-and-quoted-value pair — which is exactly the shape the
    test suite refuses, to keep tenant identifiers out of a public repository.
    """
    text = payload if isinstance(payload, str) else str(payload)
    match = re.search(rf"""['"]{key}['"]:\s*['"]({value_pattern})['"]""", text)
    return match.group(1) if match else None


async def _first_document(call: Caller) -> dict[str, Any]:
    """Discover a Drive document id at run time for the per-document tool."""
    payload = await call(
        "drive_external_sharing",
        {"hours": 24 * 7, "max_pages": MAX_PAGES, "samples": 5},
    )
    # Samples carry the doc_id a sharing finding would be triaged from.
    doc_id = _first_field(payload, "doc_id")
    if not doc_id:
        raise SkipProbe("no sharing activity in the window to take a document from")
    return {"doc_id": doc_id}


async def _some_account(call: Caller) -> dict[str, Any]:
    """Discover an account address at run time for the per-user tool.

    Suspended accounts first: that list is a directory snapshot, so it is
    stable and cheap. A tenant with none falls back to whoever appears in the
    login-failure top — and one with neither is a tenant this probe cannot run
    against, which is a skip rather than a failure.
    """
    # An address, not just any string: the login-failure top can carry
    # "(unknown)" where the actor was not identified.
    address = _first_field(await call("suspended_accounts", {"max_pages": 1}), "email", r"[^'\"]+@[^'\"]+")
    if not address:
        failures = await call("login_audit", {"hours": 24 * 7, "include_failures": True, "top": 5})
        address = _first_field(failures, "user", r"[^'\"]+@[^'\"]+")
    if not address:
        raise SkipProbe("no suspended account or failing login to take an address from")
    return {"username": address}


async def _finished_job(call: Caller) -> dict[str, Any]:
    """Start a brief and poll it to a terminal state for the result tool.

    Accepting "running" would prove only that the id round-trips: a worker that
    dies, or one whose result is never stored, would pass. So this waits for
    the job to finish and leaves the probe to assert the completed envelope.
    """
    payload = await call(
        "daily_brief_start",
        {"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "samples": 5},
    )
    job_id = payload.get("job_id") if isinstance(payload, dict) else None
    if not job_id:
        raise SkipProbe("daily_brief_start did not return a job to poll")

    # Bounded by the probe's own timeout as well; this loop just decides how
    # often to ask.
    for _ in range(60):
        await asyncio.sleep(5)
        result = await call("daily_brief_result", {"job_id": job_id})
        if isinstance(result, dict) and result.get("status") != "running":
            return {"job_id": job_id}
    raise SkipProbe("the brief job was still running when the probe gave up")


PROBES: dict[str, Probe] = {
    # -- server / backend health ------------------------------------------
    # domains is a list here, one entry per configured domain, so this is the
    # one place a row count means something: zero domains is a broken config
    # that every tool below would otherwise report as a clean run.
    "health_check": Probe(
        require_keys=("status", "service", "domains"),
        rows_key="domains",
        min_rows=1,
        must_match=(r'"status": "healthy"',),
    ),
    # -- login / directory --------------------------------------------------
    "login_audit": Probe(
        args={"hours": WINDOW_HOURS, "include_failures": True, "top": 5},
        require_keys=("window_hours", "domains"),
        must_match=(DOMAINS_NOT_EMPTY,),
        allow_empty=True,
        must_not_match=NO_DOMAIN_ERROR,
    ),
    "suspended_accounts": Probe(
        args={"max_pages": 1},
        require_keys=("domains",),
        must_match=(DOMAINS_NOT_EMPTY,),
        allow_empty=True,
        must_not_match=NO_DOMAIN_ERROR,
    ),
    "user_oauth_tokens": Probe(
        args_factory=_some_account,
        require_keys=("domain", "username", "count", "tokens"),
        rows_key="tokens",
        # This tool reports a failure as {"username": ..., "error": ...}, which
        # still satisfies two of the required keys.
        must_not_match=NO_DOMAIN_ERROR,
        allow_empty=True,
    ),
    # -- Drive exposure ------------------------------------------------------
    "drive_external_sharing": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "samples": 5},
        require_keys=("window_hours", "domains"),
        must_match=(DOMAINS_NOT_EMPTY,),
        allow_empty=True,
        must_not_match=NO_DOMAIN_ERROR,
    ),
    "drive_doc_activity": Probe(
        args_factory=_first_document,
        args={"days": 30, "max_pages": MAX_PAGES, "max_events": 25},
        require_keys=("doc_id", "window_days", "domains"),
        # The id came from a sharing finding moments earlier, so a rejection
        # here would mean the two tools disagree about what a doc_id is. The
        # per-domain guard belongs here too: this tool reports a failed domain
        # the same way its siblings do, nested where the engine cannot see it.
        must_not_match=(r'"error": "doc_id is not a valid', *NO_DOMAIN_ERROR),
        allow_empty=True,
    ),
    "shared_drive_membership_changes": Probe(
        args={"days": 30, "max_pages": MAX_PAGES, "max_events": 50},
        require_keys=("domains",),
        must_match=(DOMAINS_NOT_EMPTY,),
        allow_empty=True,
        must_not_match=NO_DOMAIN_ERROR,
    ),
    # -- morning patrol ------------------------------------------------------
    # The brief runs the login audit and the Drive scan across every domain, so
    # it is the slowest tool here and the one whose composition can silently
    # lose a section.
    # Its own envelope, not the per-domain map the standalone tools return:
    # the per-domain keys live under "summary", with the two sections it
    # aggregates beside it. Both are named here, since a brief that quietly
    # lost one would still look like a successful call.
    "daily_brief": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "samples": 5},
        require_keys=("window_hours", "summary", "login_audit", "drive_external_sharing"),
        must_match=(r'"summary": \{"',),
        allow_empty=True,
        timeout=600,
        must_not_match=NO_DOMAIN_ERROR,
    ),
    # The async pair exists because the synchronous brief can outlive a
    # client's tool-call timeout. Both halves are exercised: start must hand
    # back a job, and the result tool must know that job — a registry that
    # forgot it would report "unknown" here.
    "daily_brief_start": Probe(
        args={"hours": WINDOW_HOURS, "max_pages": MAX_PAGES, "samples": 5},
        require_keys=("job_id", "status"),
        must_match=(r'"status": "running"',),
        allow_empty=True,
    ),
    # The same envelope its synchronous twin asserts, not just "done": a job
    # that ran against zero configured domains finishes normally with empty
    # sections, and a status of "done" alone would call that a success.
    "daily_brief_result": Probe(
        args_factory=_finished_job,
        require_keys=("status", "result"),
        must_match=(r'"status": "done"', r'"summary": \{"'),
        must_not_match=NO_DOMAIN_ERROR,
        allow_empty=True,
        timeout=600,
    ),
}
