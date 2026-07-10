"""Tests for the MCP tools (aggregation, external/grant classification, degradation)."""

import inspect

import pytest

import gwsadm_mcp.server as server
from gwsadm_mcp.client import GwsError


class FakeDomainClient:
    def __init__(self, domain, canned, auth="ok"):
        self.domain = domain
        self._canned = canned  # {(application_name, event_name): (items, capped) | Exception}
        self._auth = auth
        self.calls = []

    def fetch_activities(self, application_name, *, start, end=None, event_name=None, max_pages=5):
        self.calls.append((application_name, event_name, max_pages))
        got = self._canned.get((application_name, event_name), ([], False))
        if isinstance(got, Exception):
            raise got
        return got

    def check(self):
        return {"domain": self.domain, "auth": self._auth}


def _item(email, event_name, params=None, time="2026-07-01T00:00:00.000Z", ip=None, profile_id=None):
    ev = {"name": event_name}
    if params:
        plist = []
        for k, v in params.items():
            plist.append({"name": k, "multiValue": v} if isinstance(v, list) else {"name": k, "value": v})
        ev["parameters"] = plist
    actor = {"email": email}
    if profile_id is not None:
        actor["profileId"] = profile_id
    item = {"id": {"time": time}, "actor": actor, "events": [ev]}
    if ip is not None:
        item["ipAddress"] = ip
    return item


@pytest.fixture
def inject(monkeypatch):
    def _inject(clients, internal):
        monkeypatch.setitem(server._state, "clients", clients)
        monkeypatch.setitem(server._state, "internal", internal)

    return _inject


def test_login_audit_collects_disabled_and_failures(inject):
    canned = {
        ("login", "account_disabled_spamming"): (
            [_item("s1@students.example.edu", "account_disabled_spamming")],
            False,
        ),
        ("login", "login_failure"): (
            [_item("u@example.edu", "login_failure")] * 3 + [_item("v@example.edu", "login_failure")],
            True,
        ),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    out = server.login_audit(hours=24)
    dom = out["domains"]["example.edu"]
    assert dom["account_disabled"]["entries"][0]["user"] == "s1@students.example.edu"
    assert dom["account_disabled"]["entries"][0]["event"] == "account_disabled_spamming"
    assert dom["account_disabled"]["capped"] is False
    assert dom["login_failures"]["total"] == 4
    assert dom["login_failures"]["capped"] is True
    assert dom["login_failures"]["top"][0] == {"user": "u@example.edu", "count": 3}


def test_login_audit_entry_surfaces_ip_and_falls_back_to_profile_id(inject):
    # suspicious_login events can omit actor.email entirely (observed in
    # production); ipAddress and actor.profileId are far more reliably
    # populated and must still make the entry investigable.
    with_email = _item("s1@students.example.edu", "suspicious_login", ip="203.0.113.5", profile_id="1234567890")
    no_email = {
        "id": {"time": "2026-07-01T00:00:00.000Z"},
        "actor": {"profileId": "999888777"},
        "ipAddress": "198.51.100.9",
        "events": [{"name": "suspicious_login"}],
    }
    no_email_no_profile = {
        "id": {"time": "2026-07-01T00:00:00.000Z"},
        "actor": {},
        "ipAddress": "198.51.100.42",
        "events": [{"name": "suspicious_login"}],
    }
    canned = {
        ("login", "suspicious_login"): ([with_email, no_email, no_email_no_profile], False),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    entries = server.login_audit(hours=24)["domains"]["example.edu"]["suspicious_logins"]["entries"]

    assert entries[0]["user"] == "s1@students.example.edu"
    assert entries[0]["ip"] == "203.0.113.5"

    assert entries[1]["user"] == "999888777"  # falls back to profileId
    assert entries[1]["ip"] == "198.51.100.9"

    assert entries[2]["user"] is None  # neither email nor profileId available
    assert entries[2]["ip"] == "198.51.100.42"  # IP still recoverable


def test_login_audit_capped_probe_yields_no_phantom_entries(inject):
    canned = {("login", "account_disabled_spamming"): ([], True)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.login_audit(hours=24)["domains"]["example.edu"]
    assert dom["account_disabled"]["entries"] == []  # no note dict mixed in
    assert dom["account_disabled"]["capped"] is True


def test_login_audit_unknown_domain_is_error(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    assert "error" in server.login_audit(domain="nope.example")


def test_select_normalizes_case_and_whitespace(inject):
    canned = {}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    out = server.login_audit(domain="  EXAMPLE.EDU ", include_failures=False)
    assert "example.edu" in out["domains"]


def test_one_domain_error_does_not_poison_others(inject):
    ok = FakeDomainClient("a.example.edu", {})
    boom = FakeDomainClient(
        "b.example.edu",
        {("login", "account_disabled_password_leak"): GwsError("[b.example.edu] boom")},
    )
    # A GwsError on one event name is tolerated per-event; make ALL probes fail
    for name in server.ACCOUNT_DISABLED_EVENTS + server.SUSPICIOUS_LOGIN_EVENTS + ("login_failure",):
        boom._canned[("login", name)] = GwsError("boom")
    inject([ok, boom], {"a.example.edu", "b.example.edu"})
    out = server.login_audit(hours=24)
    assert "account_disabled" in out["domains"]["a.example.edu"]  # healthy domain intact
    b = out["domains"]["b.example.edu"]
    # per-event failures are recorded, and the failure of login_failure fetch
    # degrades only this domain
    assert "error" in b or b["account_disabled"].get("event_errors")


def test_drive_external_grant_counted_revocation_excluded(inject):
    items_grant = [
        _item(
            "owner@example.edu",
            "change_user_access",
            {
                "target_user": "ext@gmail.com",
                "doc_title": "Plan",
                "doc_id": "d1",
                "new_value": ["can_edit"],
                "visibility": "shared_externally",
                "old_visibility": "shared_externally",
            },
        ),
    ]
    items_revoke = [
        _item(
            "owner@example.edu",
            "change_user_access",
            {
                "target_user": "gone@gmail.com",
                "doc_title": "Old",
                "new_value": ["none"],
                "visibility": "private",
                "old_visibility": "shared_externally",
            },
        ),
    ]
    canned = {("drive", "change_user_access"): (items_grant + items_revoke, False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_top"] == [{"target": "ext@gmail.com", "count": 1}]
    assert dom["external_targets_total"] == 1
    assert dom["external_access_revoked"] == 1
    assert {s["target_user"] for s in dom["external_samples"]} == {"ext@gmail.com"}


def test_drive_risky_requires_visibility_transition(inject):
    became_public = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "people_with_link", "old_visibility": "private", "doc_title": "Now open"},
    )
    already_public = _item(
        "o@example.edu",
        "change_user_access",
        {
            "target_user": "peer@example.edu",
            "visibility": "shared_externally",
            "old_visibility": "shared_externally",
            "new_value": ["can_edit"],
            "doc_title": "Already shared",
        },
    )
    canned = {
        ("drive", "change_document_access_scope"): ([became_public], False),
        ("drive", "change_user_access"): ([already_public], False),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1  # only the transition counts
    assert {s["doc_title"] for s in dom["exposure_samples"]} == {"Now open"}
    assert dom["exposure_samples"][0]["old_visibility"] == "private"


def test_drive_public_to_link_narrowing_is_not_new_exposure(inject):
    # Going from "anyone with the link, findable by search" down to
    # "anyone with the link" is a reduction in exposure, not a new one.
    narrowed = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "people_with_link", "old_visibility": "public_on_the_web", "doc_title": "Narrowed"},
    )
    widened = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "public_on_the_web", "old_visibility": "people_with_link", "doc_title": "Widened"},
    )
    canned = {("drive", "change_document_access_scope"): ([narrowed, widened], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1  # only the escalation counts
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["Widened"]


def test_drive_change_document_visibility_is_a_duplicate_sibling_and_does_not_double_count(inject):
    # Google emits change_document_visibility and change_document_access_scope
    # as simultaneous sibling events reporting the SAME transition (live data:
    # 361/363 sampled link/public transitions, and every sampled domain-scope
    # grant, appear on both). Classifying both would double every count.
    ext_grant_scope = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "partner.example",
            "doc_title": "Shared",
            "visibility": "shared_externally",
            "old_visibility": "private",
        },
        time="2026-07-01T00:00:00.000Z",
    )
    ext_grant_vis = _item(
        "o@example.edu",
        "change_document_visibility",
        {
            "target_domain": "partner.example",
            "doc_title": "Shared",
            "visibility": "shared_externally",
            "old_visibility": "private",
        },
        time="2026-07-01T00:00:00.000Z",
    )
    exposure_scope = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "people_with_link", "old_visibility": "private", "doc_title": "Open"},
        time="2026-07-01T00:01:00.000Z",
    )
    exposure_vis = _item(
        "o@example.edu",
        "change_document_visibility",
        {"visibility": "people_with_link", "old_visibility": "private", "doc_title": "Open"},
        time="2026-07-01T00:01:00.000Z",
    )
    untargeted_scope = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "all",
            "visibility": "shared_externally",
            "old_visibility": "private",
            "doc_title": "Anyone with link",
        },
        time="2026-07-01T00:02:00.000Z",
    )
    untargeted_vis = _item(
        "o@example.edu",
        "change_document_visibility",
        {
            "target_domain": "all",
            "visibility": "shared_externally",
            "old_visibility": "private",
            "doc_title": "Anyone with link",
        },
        time="2026-07-01T00:02:00.000Z",
    )
    canned = {
        ("drive", "change_document_access_scope"): (
            [ext_grant_scope, exposure_scope, untargeted_scope],
            False,
        ),
        ("drive", "change_document_visibility"): (
            [ext_grant_vis, exposure_vis, untargeted_vis],
            False,
        ),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 1  # not 2
    assert dom["external_targets_top"] == [{"target": "partner.example", "count": 1}]
    assert dom["risky_visibility_events"] == 1  # not 2
    assert dom["untargeted_external_transitions"] == 1  # not 2
    # acl_events bookkeeping still reflects both probes independently.
    assert dom["acl_events"]["change_document_access_scope"] == 3
    assert dom["acl_events"]["change_document_visibility"] == 3


def test_drive_cross_internal_domain_share_is_not_external_nor_risky(inject):
    # Google marks any grant outside the file OWNER's domain as
    # "shared_externally" — a student-domain -> staff-domain Classroom
    # submission must be classified by the configured internal domains,
    # not by Google's owner-relative flag.
    submission = _item(
        "stud@students.example.edu",
        "change_user_access",
        {
            "target_user": "teacher@example.edu",
            "doc_title": "homework.pdf",
            "new_value": ["can_edit"],
            "visibility": "shared_externally",
            "old_visibility": "private",
        },
    )
    self_removal = _item(
        "stud@students.example.edu",
        "change_user_access",
        {
            "target_user": "stud@students.example.edu",
            "doc_title": "homework.pdf",
            "new_value": ["none"],
            "visibility": "shared_externally",
            "old_visibility": "private",
        },
    )
    canned = {("drive", "change_user_access"): ([submission, self_removal], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu", "students.example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 0
    assert dom["risky_visibility_events"] == 0
    assert dom["untargeted_external_transitions"] == 0  # target present → classifiable
    assert dom["external_samples"] == []
    assert dom["exposure_samples"] == []


def test_drive_untargeted_shared_externally_transition_surfaced_separately(inject):
    # A no-target shared_externally visibility change cannot be classified
    # against internal domains: not risky (owner-domain-relative flag), not
    # external, but surfaced as a residual counter (change_document_access_scope
    # is the canonical source; see the sibling-dedup test for why
    # change_document_visibility itself must not independently count).
    vis = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "shared_externally", "old_visibility": "private", "doc_title": "Doc"},
    )
    # Narrowing from link visibility down to named-external is NOT new exposure.
    narrowing = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "shared_externally", "old_visibility": "people_with_link", "doc_title": "Narrowed"},
    )
    # target_domain == "all" is not a classifiable domain: residual bucket.
    all_scope = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "all",
            "visibility": "shared_externally",
            "old_visibility": "private",
            "doc_title": "All scope",
        },
    )
    # No transition at all (old == new) must not be counted.
    no_transition = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "shared_externally", "old_visibility": "shared_externally", "doc_title": "No-op"},
    )
    # Bookkeeping events (change_acl_editors) duplicate a paired targeted
    # event and must stay out of the residual bucket.
    bookkeeping = _item(
        "o@example.edu",
        "change_acl_editors",
        {"visibility": "shared_externally", "old_visibility": "private", "doc_title": "Sibling noise"},
    )
    canned = {
        ("drive", "change_document_access_scope"): ([vis, narrowing, all_scope, no_transition], False),
        ("drive", "change_acl_editors"): ([bookkeeping], False),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 0
    assert dom["exposure_samples"] == []
    assert dom["external_targets_total"] == 0
    assert dom["untargeted_external_transitions"] == 2
    assert [s["doc_title"] for s in dom["untargeted_samples"]] == ["Doc", "All scope"]


def test_drive_domain_scoped_grant_classified_by_target_domain(inject):
    # Domain-scoped grants (e.g. "anyone at partner.edu") carry target_domain
    # but no target_user; the bare domain is judged against internal_domains.
    ext_dom = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "Partner.example",
            "doc_title": "For partner",
            "visibility": "shared_externally",
            "old_visibility": "private",
            "new_value": ["can_view"],
        },
    )
    int_dom = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "students.example.edu",
            "doc_title": "For students",
            "visibility": "shared_externally",
            "old_visibility": "private",
            "new_value": ["can_view"],
        },
    )
    all_dom = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "target_domain": "all",
            "doc_title": "For anyone",
            "visibility": "people_with_link",
            "old_visibility": "private",
            "new_value": ["can_view"],
        },
    )
    canned = {("drive", "change_document_access_scope"): ([ext_dom, int_dom, all_dom], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu", "students.example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_top"] == [{"target": "partner.example", "count": 1}]
    assert [s["doc_title"] for s in dom["external_samples"]] == ["For partner"]
    assert dom["risky_visibility_events"] == 1  # "all" scope = link visibility transition
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["For anyone"]
    # none reach the residual bucket: the first two have a classifiable
    # target_domain, and "all" is counted as exposure above instead.
    assert dom["untargeted_external_transitions"] == 0


def test_drive_capped_events_names_the_partial_probes(inject):
    canned = {
        ("drive", "change_user_access"): (
            [_item("o@example.edu", "change_user_access", {"target_user": "e@gmail.com", "new_value": ["can_view"]})],
            True,
        ),
        ("drive", "change_document_visibility"): ([], False),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["capped"] is True
    assert dom["capped_events"] == ["change_user_access"]


def test_daily_brief_passes_max_pages_and_samples_to_drive_scan(inject):
    items = [
        _item("o@example.edu", "change_user_access", {"target_user": f"x{i}@gmail.com", "new_value": ["can_view"]})
        for i in range(5)
    ]
    client = FakeDomainClient("example.edu", {("drive", "change_user_access"): (items, False)})
    inject([client], {"example.edu"})
    out = server.daily_brief(hours=24, max_pages=9, samples=3)
    drive_pages = {mp for app, _, mp in client.calls if app == "drive"}
    assert drive_pages == {9}
    dom = out["drive_external_sharing"]["example.edu"]
    assert dom["external_targets_total"] == 5  # counters see everything
    assert len(dom["external_samples"]) == 3  # the samples budget is honored


def test_daily_brief_default_page_budget_matches_standalone_tool(inject):
    # Issue: daily_brief once hardcoded max_pages=3 while the standalone tool
    # defaulted to 5, so both reported different numbers for the same window.
    client = FakeDomainClient("example.edu", {})
    inject([client], {"example.edu"})
    server.daily_brief(hours=24)
    standalone = inspect.signature(server.drive_external_sharing).parameters["max_pages"].default
    drive_pages = {mp for app, _, mp in client.calls if app == "drive"}
    assert drive_pages == {standalone}


def test_drive_external_grant_with_link_transition_counted_in_both(inject):
    # A grant can be external AND flip the doc to link visibility in the same
    # event; it must appear in both counters and both sample lists.
    ev = _item(
        "o@example.edu",
        "change_user_access",
        {
            "target_user": "ext@gmail.com",
            "doc_title": "Open plan",
            "doc_id": "d9",
            "new_value": ["can_view"],
            "visibility": "people_with_link",
            "old_visibility": "private",
        },
    )
    canned = {("drive", "change_user_access"): ([ev], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 1
    assert dom["risky_visibility_events"] == 1
    assert [s["target_user"] for s in dom["external_samples"]] == ["ext@gmail.com"]
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["Open plan"]


def test_drive_multivalue_and_case_variant_params_are_tolerated(inject):
    # target_user / visibility are documented single-valued but must not
    # crash the whole call if delivered as multiValue; case-variant target
    # addresses count as one recipient. Samples show the normalized value,
    # not the raw (possibly list/mixed-case) parameter.
    weird_target = _item(
        "o@example.edu", "change_user_access", {"target_user": ["ext@gmail.com"], "new_value": ["can_view"]}
    )
    case_variant = _item(
        "o@example.edu", "change_user_access", {"target_user": "Ext@Gmail.com", "new_value": ["can_view"]}
    )
    weird_visibility = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": ["people_with_link"], "old_visibility": "private"},
    )
    canned = {
        ("drive", "change_user_access"): ([weird_target, case_variant], False),
        ("drive", "change_document_access_scope"): ([weird_visibility], False),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_top"] == [{"target": "ext@gmail.com", "count": 2}]
    assert dom["external_targets_total"] == 1
    assert dom["risky_visibility_events"] == 1
    assert {s["target_user"] for s in dom["external_samples"]} == {"ext@gmail.com"}
    assert dom["exposure_samples"][0]["visibility"] == "people_with_link"


def test_drive_exposure_counted_when_old_visibility_missing(inject):
    # Production link-enable events often carry no usable prior state
    # (old_visibility absent or "unknown"); they must still count as exposure.
    ev = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "people_with_link", "doc_title": "No prior state"},
    )
    canned = {("drive", "change_document_access_scope"): ([ev], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1
    assert dom["exposure_samples"][0]["old_visibility"] is None


def test_drive_self_creation_grant_excluded_from_risky_visibility(inject):
    # A user creating their own new Form/Sheet/Doc grants themselves "owner"
    # on a file with no prior ACL state (old_visibility "unknown" -> a default
    # visibility). This is document creation, not exposure of anything
    # pre-existing, and must not inflate risky_visibility_events.
    self_creation = _item(
        "teacher@example.edu",
        "change_user_access",
        {
            "target_user": "teacher@example.edu",
            "doc_title": "New quiz",
            "new_value": ["owner"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
        },
    )
    # A genuine widening by someone else on an existing file must still count,
    # even with the same visibility/old_visibility shape.
    real_widening = _item(
        "teacher@example.edu",
        "change_user_access",
        {
            "target_user": "student@example.edu",
            "doc_title": "Shared syllabus",
            "new_value": ["can_edit"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
        },
    )
    canned = {("drive", "change_user_access"): ([self_creation, real_widening], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["Shared syllabus"]


def test_drive_self_creation_grant_excluded_with_no_target_named(inject):
    # change_acl_editors is a sibling bookkeeping event for the same file
    # creation as change_user_access, but often carries no target_user at
    # all — just the resulting owner/writers list. Must still be excluded
    # when the event's own "owner" param corroborates it's the actor's own
    # file (owner == actor).
    creation_echo = _item(
        "teacher@example.edu",
        "change_acl_editors",
        {
            "doc_title": "New quiz",
            "new_value": ["owner", "writers"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
            "owner": "teacher@example.edu",
        },
    )
    # A real third party granted owner (not the actor, target present) must
    # still count even with the same missing-prior-state shape.
    real_transfer = _item(
        "teacher@example.edu",
        "change_acl_editors",
        {
            "target_user": "colleague@example.edu",
            "doc_title": "Handed off",
            "new_value": ["owner"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
        },
    )
    canned = {("drive", "change_acl_editors"): ([creation_echo, real_transfer], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["Handed off"]


def test_drive_no_target_and_no_owner_match_is_not_self_creation(inject):
    # No target_user AND no owner corroboration (owner absent, or owner is
    # someone other than the actor) must NOT be excluded — e.g. an admin
    # bulk-transferring ownership of a pre-existing, already-shared file
    # during account offboarding: actor is the admin, no named target, and
    # the resulting owner is the new owner, not the admin. This is
    # indistinguishable from a creation echo by target_user alone; "owner"
    # is what tells them apart.
    admin_bulk_transfer = _item(
        "admin@example.edu",
        "change_acl_editors",
        {
            "doc_title": "Offboarded employee's shared doc",
            "new_value": ["owner"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
            "owner": "newowner@example.edu",
        },
    )
    # owner param absent entirely: can't confirm self-action, so the
    # conservative default is to count it too.
    owner_unknown = _item(
        "admin@example.edu",
        "change_acl_editors",
        {
            "doc_title": "No owner param at all",
            "new_value": ["owner"],
            "visibility": "people_with_link",
            "old_visibility": "unknown",
        },
    )
    canned = {("drive", "change_acl_editors"): ([admin_bulk_transfer, owner_unknown], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 2
    assert {s["doc_title"] for s in dom["exposure_samples"]} == {
        "Offboarded employee's shared doc",
        "No owner param at all",
    }


def test_drive_acl_events_partition_completely_across_named_sets(inject):
    # Guard against silent drift: every DRIVE_ACL_EVENTS name must land in
    # exactly one of the three known-behavior buckets (visibility-change,
    # self-creation-grant-eligible, or neither) so a future addition to
    # DRIVE_ACL_EVENTS can't accidentally inherit self-creation-grant
    # exclusion (or lose it) without a deliberate decision.
    other_events = set(server.DRIVE_ACL_EVENTS) - server.VISIBILITY_CHANGE_EVENTS - server.SELF_CREATION_GRANT_EVENTS
    assert other_events == {
        "shared_drive_membership_change",
        "shared_drive_settings_change",
        "sheets_import_range_access_change",
    }
    assert not (server.VISIBILITY_CHANGE_EVENTS & server.SELF_CREATION_GRANT_EVENTS)


def test_drive_self_creation_grant_exclusion_never_applies_to_canonical_event(inject):
    # change_document_access_scope (CANONICAL_VISIBILITY_EVENT) has no
    # target_user parameter on this API either, and can legitimately report
    # new_value "owner" for a real, non-creation transition. The
    # self-creation-grant heuristic must be scoped away from this event name
    # (and its change_document_visibility sibling) — applying it here would
    # blind the tool's primary signal, not just remove creation noise.
    real_exposure = _item(
        "o@example.edu",
        "change_document_access_scope",
        {
            "doc_title": "Existing doc set public",
            "new_value": "owner",
            "visibility": "people_with_link",
            "old_visibility": "unknown",
        },
    )
    canned = {("drive", "change_document_access_scope"): ([real_exposure], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1
    assert [s["doc_title"] for s in dom["exposure_samples"]] == ["Existing doc set public"]


def test_drive_self_creation_grant_with_missing_actor_email_does_not_crash(inject):
    # A missing actor.email (Google reports this can be absent for
    # non-standard actors) must not crash (actor.get("email") on a bare {}
    # is safe), and — since we can no longer confirm target == actor — the
    # conservative choice is to NOT suppress: an uncertain case counts as
    # exposure rather than risking a silently dropped real grant. This is a
    # known, acceptable trade-off (occasional un-suppressed creation noise)
    # for a security-audit tool that must never miss a real signal.
    ev = {
        "id": {"time": "2026-07-01T00:00:00.000Z"},
        "actor": {},
        "events": [
            {
                "name": "change_user_access",
                "parameters": [
                    {"name": "target_user", "value": "teacher@example.edu"},
                    {"name": "doc_title", "value": "New quiz"},
                    {"name": "new_value", "multiValue": ["owner"]},
                    {"name": "visibility", "value": "people_with_link"},
                    {"name": "old_visibility", "value": "unknown"},
                ],
            }
        ],
    }
    canned = {("drive", "change_user_access"): ([ev], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["risky_visibility_events"] == 1  # uncertain -> counted, not suppressed


def test_drive_external_targets_total_not_saturated_by_top10(inject):
    items = [
        _item("o@example.edu", "change_user_access", {"target_user": f"x{i}@gmail.com", "new_value": ["can_view"]})
        for i in range(25)
    ]
    canned = {("drive", "change_user_access"): (items, False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 25
    assert len(dom["external_targets_top"]) == 10


def test_drive_event_error_recorded_not_fatal(inject):
    canned = {
        ("drive", "change_user_access"): (
            [_item("o@example.edu", "change_user_access", {"target_user": "e@gmail.com", "new_value": ["can_view"]})],
            False,
        ),
        ("drive", "sheets_import_range_access_change"): GwsError("HTTP 400"),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 1
    assert "sheets_import_range_access_change" in dom["event_errors"]
    assert dom["capped"] is True  # a fetch error is partial coverage too


def test_drive_canonical_probe_error_zeroes_classification_but_is_flagged_capped(inject):
    # change_document_visibility can no longer compensate if
    # change_document_access_scope's own fetch fails outright (round-3 review
    # finding): the window's classification counts become a lower bound of 0,
    # so this MUST surface as capped=True even with no capped_events entry.
    canned = {
        ("drive", "change_document_access_scope"): GwsError("HTTP 503"),
        ("drive", "change_document_visibility"): (
            [
                _item(
                    "o@example.edu",
                    "change_document_visibility",
                    {
                        "target_domain": "partner.example",
                        "visibility": "shared_externally",
                        "old_visibility": "private",
                        "doc_title": "Missed",
                    },
                )
            ],
            False,
        ),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["example.edu"]
    assert dom["external_targets_total"] == 0  # the sibling cannot compensate
    assert dom["capped"] is True
    assert dom["capped_events"] == []  # this is an outright error, not a page cap
    assert "change_document_access_scope" in dom["event_errors"]
    assert dom["acl_events"]["change_document_visibility"] == 1  # bookkeeping still saw it


def test_daily_brief_summarizes_and_propagates_capped(inject):
    canned = {
        ("login", "account_disabled_spamming"): (
            [_item("s1@students.example.edu", "account_disabled_spamming")],
            False,
        ),
        ("drive", "change_user_access"): (
            [_item("o@example.edu", "change_user_access", {"target_user": "x@gmail.com", "new_value": ["can_view"]})],
            True,  # drive scan capped
        ),
    }
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    out = server.daily_brief(hours=24)
    s = out["summary"]["example.edu"]
    assert s["account_disabled"] == 1
    assert s["external_sharing_targets"] == 1
    assert s["capped"] is True
    assert out["login_audit"]["example.edu"]["account_disabled"]["entries"][0]["user"] == "s1@students.example.edu"


def test_daily_brief_summary_includes_untargeted_external_transitions(inject):
    untargeted = _item(
        "o@example.edu",
        "change_document_access_scope",
        {"visibility": "shared_externally", "old_visibility": "private", "doc_title": "Doc"},
    )
    canned = {("drive", "change_document_access_scope"): ([untargeted], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    out = server.daily_brief(hours=24)
    assert out["summary"]["example.edu"]["untargeted_external_transitions"] == 1


def test_health_check_healthy(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.health_check()
    assert out["status"] == "healthy"
    assert out["service"] == "gwsadm-mcp"
    assert out["domains"] == [{"domain": "example.edu", "auth": "ok"}]


def test_health_check_degraded_when_one_domain_fails(inject):
    inject(
        [FakeDomainClient("a.example.edu", {}), FakeDomainClient("b.example.edu", {}, auth="error")],
        {"a.example.edu", "b.example.edu"},
    )
    assert server.health_check()["status"] == "degraded"


def test_health_check_config_error(monkeypatch):
    monkeypatch.setitem(server._state, "clients", None)
    monkeypatch.setattr(server, "load_config", lambda: (_ for _ in ()).throw(server.ConfigError("boom")))
    out = server.health_check()
    assert out["status"] == "error" and "boom" in out["detail"]


# --- parallel fetch (thread pool) behavior ---


def test_parallel_fetch_captures_exceptions_per_task():
    import datetime

    from gwsadm_mcp.server import _parallel_fetch

    boom = GwsError("nope")
    ok = FakeDomainClient(
        "ok.edu", {("drive", "change_user_access"): ([_item("o@ok.edu", "change_user_access")], False)}
    )
    bad = FakeDomainClient("bad.edu", {("drive", "change_user_access"): boom})
    res = _parallel_fetch(
        [
            (ok, "drive", "change_user_access", 5),
            (bad, "drive", "change_user_access", 5),
        ],
        datetime.datetime.now(datetime.timezone.utc),
    )
    assert res[("ok.edu", "drive", "change_user_access")][0][0]["actor"]["email"] == "o@ok.edu"
    assert isinstance(res[("bad.edu", "drive", "change_user_access")], GwsError)


def test_login_audit_two_domains_run_in_parallel_without_cross_contamination(inject):
    a = FakeDomainClient("a.edu", {("login", "suspicious_login"): ([_item("x@a.edu", "suspicious_login")], False)})
    b = FakeDomainClient("b.edu", {("login", "gov_attack_warning"): ([_item("y@b.edu", "gov_attack_warning")], False)})
    inject([a, b], {"a.edu", "b.edu"})
    domains = server.login_audit(hours=24)["domains"]
    a_susp = domains["a.edu"]["suspicious_logins"]["entries"]
    b_susp = domains["b.edu"]["suspicious_logins"]["entries"]
    assert len(a_susp) == 1 and len(b_susp) == 1
    # each domain aggregated only its own actor — no thread cross-talk
    assert a_susp[0]["user"] == "x@a.edu"
    assert b_susp[0]["user"] == "y@b.edu"


# --- error-degradation invariant under the parallel path ---
# GwsAuthError subclasses GwsError, so whole-domain (auth) vs per-event (plain)
# degradation is decided solely by the isinstance ordering in the aggregators.
# These pin that ordering so a future reorder fails CI.


def test_login_auth_error_degrades_whole_domain_and_spares_siblings(inject):
    from gwsadm_mcp.client import GwsAuthError

    bad = FakeDomainClient("bad.edu", {("login", "suspicious_login"): GwsAuthError("[bad.edu] auth failed")})
    ok = FakeDomainClient(
        "ok.edu", {("login", "gov_attack_warning"): ([_item("y@ok.edu", "gov_attack_warning")], False)}
    )
    inject([bad, ok], {"bad.edu", "ok.edu"})
    domains = server.login_audit(hours=24)["domains"]
    assert list(domains["bad.edu"].keys()) == ["error"]  # auth is domain-wide, not one event_error
    assert domains["ok.edu"]["suspicious_logins"]["entries"][0]["user"] == "y@ok.edu"  # sibling intact


def test_login_plain_error_marks_only_that_event(inject):
    canned = {
        ("login", "suspicious_login"): GwsError("[e.edu] reports API error: HTTP 500"),
        ("login", "gov_attack_warning"): ([_item("y@e.edu", "gov_attack_warning")], False),
        ("login", "login_failure"): ([_item("f@e.edu", "login_failure")], False),
    }
    inject([FakeDomainClient("e.edu", canned)], {"e.edu"})
    dom = server.login_audit(hours=24)["domains"]["e.edu"]
    assert "error" not in dom  # a plain GwsError does NOT degrade the whole domain
    assert "suspicious_login" in dom["suspicious_logins"]["event_errors"]  # only that probe marked
    assert dom["suspicious_logins"]["entries"][0]["user"] == "y@e.edu"  # sibling event survived
    assert dom["login_failures"]["total"] == 1  # other counters intact


def test_drive_auth_error_degrades_whole_domain(inject):
    from gwsadm_mcp.client import GwsAuthError

    canned = {("drive", "change_user_access"): GwsAuthError("[e.edu] auth failed")}
    inject([FakeDomainClient("e.edu", canned)], {"e.edu"})
    dom = server.drive_external_sharing(hours=24)["domains"]["e.edu"]
    assert list(dom.keys()) == ["error"]  # one auth-failed probe fails the whole domain


def test_daily_brief_auth_error_degrades_domain_summary(inject):
    from gwsadm_mcp.client import GwsAuthError

    canned = {("login", "suspicious_login"): GwsAuthError("[e.edu] auth failed")}
    inject([FakeDomainClient("e.edu", canned)], {"e.edu"})
    out = server.daily_brief(hours=24)
    assert out["summary"]["e.edu"] == {"error": "[e.edu] auth failed"}
