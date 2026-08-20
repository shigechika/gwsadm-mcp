"""Tests for the MCP tools (aggregation, external/grant classification, degradation)."""

import inspect

import pytest

import gwsadm_mcp.server as server
from gwsadm_mcp.client import GwsError


class FakeDomainClient:
    def __init__(
        self,
        domain,
        canned,
        auth="ok",
        suspended=None,
        user=None,
        tokens=None,
        gmail_messages=None,
        group_settings=None,
        group_meta=None,
        group_members=None,
    ):
        self.domain = domain
        self._canned = canned  # {(application_name, event_name): (items, capped) | Exception}
        self._auth = auth
        self._suspended = suspended  # (users, capped) | Exception | None
        # user: dict (found) | Exception | None (not found) -- None is the
        # not-found answer here rather than "unset", matching the real
        # client's 404 return, so the default double reports a lookup for an
        # account no test has canned as not-found instead of inventing one.
        self._user = user
        self._tokens = tokens  # list[dict] | Exception | None
        # gmail_messages: dict[user_email, dict | None | Exception] | Exception
        # (a bare Exception applies to every recipient, for the "whole domain
        # lacks the scope" case; a per-user dict lets one test cover a mixed
        # found/not-found/error recipient list against a single client)
        self._gmail_messages = gmail_messages
        # group_settings / group_meta / group_members: dict[group_email, ... | Exception] | Exception | None
        # (same shape convention as gmail_messages above; group_members values
        # are (members, capped) tuples, matching the real client's return shape)
        self._group_settings = group_settings
        self._group_meta = group_meta
        self._group_members = group_members
        self.calls = []
        self.user_calls = []
        self.token_calls = []
        self.gmail_calls = []
        self.group_settings_calls = []
        self.group_meta_calls = []
        self.group_members_calls = []

    def fetch_activities(self, application_name, *, start, end=None, event_name=None, filters=None, max_pages=5):
        self.calls.append((application_name, event_name, max_pages, filters))
        # Filtered (doc-scoped) fetches are canned under (application, filters).
        got = self._canned.get((application_name, filters if filters else event_name), ([], False))
        if isinstance(got, Exception):
            raise got
        return got

    def list_suspended_users(self, *, max_pages=20):
        if self._suspended is None:
            return [], False
        if isinstance(self._suspended, Exception):
            raise self._suspended
        return self._suspended

    def get_user(self, user_key):
        self.user_calls.append(user_key)
        if isinstance(self._user, Exception):
            raise self._user
        return self._user  # a dict (found) or None (no such account)

    def list_user_oauth_tokens(self, user_key):
        self.token_calls.append(user_key)
        if self._tokens is None:
            return []
        if isinstance(self._tokens, Exception):
            raise self._tokens
        return self._tokens

    def find_message_by_id(self, user_email, message_id):
        self.gmail_calls.append((user_email, message_id))
        if self._gmail_messages is None:
            return None
        if isinstance(self._gmail_messages, Exception):
            raise self._gmail_messages
        got = self._gmail_messages.get(user_email)
        if isinstance(got, Exception):
            raise got
        return got  # a dict (found) or None (not found) — caller's choice per user

    def get_group_settings(self, group_email):
        self.group_settings_calls.append(group_email)
        if self._group_settings is None:
            return {}
        if isinstance(self._group_settings, Exception):
            raise self._group_settings
        got = self._group_settings.get(group_email)
        if isinstance(got, Exception):
            raise got
        return got

    def get_group(self, group_email):
        self.group_meta_calls.append(group_email)
        if self._group_meta is None:
            return {}
        if isinstance(self._group_meta, Exception):
            raise self._group_meta
        got = self._group_meta.get(group_email)
        if isinstance(got, Exception):
            raise got
        return got

    def list_group_members(self, group_email, *, max_pages=20):
        self.group_members_calls.append((group_email, max_pages))
        if self._group_members is None:
            return [], False
        if isinstance(self._group_members, Exception):
            raise self._group_members
        got = self._group_members.get(group_email)
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


def test_login_audit_names_the_account_google_itself_acted_on(inject):
    # Google-initiated security events carry actor {"callerType": "KEY", "key":
    # "Google"} -- no email, no profileId, because Google acted -- and name the
    # affected account in affected_email_address. Reading only the actor
    # anonymised exactly these entries: a real compromise (2026-08-20) was
    # collected and shown as user: null, so it could not be matched to the
    # ticket asking about that mailbox. Shape copied from a production activity.
    google_disabled = {
        "id": {"time": "2026-08-19T11:22:22.195Z"},
        "actor": {"callerType": "KEY", "key": "Google"},
        "ipAddress": "203.0.113.77",
        "events": [
            {
                "type": "account_warning",
                "name": "account_disabled_spamming",
                "parameters": [{"name": "affected_email_address", "value": "victim@example.edu"}],
            }
        ],
    }
    canned = {("login", "account_disabled_spamming"): ([google_disabled], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    entries = server.login_audit(hours=24)["domains"]["example.edu"]["account_disabled"]["entries"]

    assert entries[0]["user"] == "victim@example.edu"  # the account, not the actor
    assert entries[0]["ip"] == "203.0.113.77"
    assert entries[0]["event"] == "account_disabled_spamming"


def test_login_audit_prefers_the_actor_over_affected_email(inject):
    # Guards the precedence: affected_email_address is a last resort, so an
    # event that has both must still report the actor. Otherwise a
    # human-initiated event carrying an affected address (an admin acting on
    # someone else) would silently start naming the target instead of the admin.
    both = {
        "id": {"time": "2026-08-19T11:22:22.195Z"},
        "actor": {"email": "admin@example.edu"},
        "ipAddress": "203.0.113.78",
        "events": [
            {
                "name": "suspicious_login",
                "parameters": [{"name": "affected_email_address", "value": "target@example.edu"}],
            }
        ],
    }
    canned = {("login", "suspicious_login"): ([both], False)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    entries = server.login_audit(hours=24)["domains"]["example.edu"]["suspicious_logins"]["entries"]

    assert entries[0]["user"] == "admin@example.edu"


def test_login_audit_capped_probe_yields_no_phantom_entries(inject):
    canned = {("login", "account_disabled_spamming"): ([], True)}
    inject([FakeDomainClient("example.edu", canned)], {"example.edu"})
    dom = server.login_audit(hours=24)["domains"]["example.edu"]
    assert dom["account_disabled"]["entries"] == []  # no note dict mixed in
    assert dom["account_disabled"]["capped"] is True


def test_login_audit_unknown_domain_is_error(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    assert "error" in server.login_audit(domain="nope.example")


def test_suspended_accounts_projects_and_counts(inject):
    suspended = (
        [
            {
                "primaryEmail": "old@students.example.edu",
                "suspensionReason": "ADMIN",
                "lastLoginTime": "2019-04-01T00:00:00.000Z",
                "creationTime": "2011-04-06T00:00:00.000Z",
                "orgUnitPath": "/Students",
            }
        ],
        False,
    )
    inject([FakeDomainClient("example.edu", {}, suspended=suspended)], {"example.edu"})
    dom = server.suspended_accounts()["domains"]["example.edu"]
    assert dom["count"] == 1
    assert dom["capped"] is False
    acct = dom["accounts"][0]
    assert acct["email"] == "old@students.example.edu"
    assert acct["suspension_reason"] == "ADMIN"
    assert acct["org_unit"] == "/Students"


def test_suspended_accounts_degrades_per_domain_on_auth_error(inject):
    from gwsadm_mcp.client import GwsAuthError

    ok = FakeDomainClient("a.example.edu", {}, suspended=([{"primaryEmail": "x@a.example.edu"}], False))
    boom = FakeDomainClient("b.example.edu", {}, suspended=GwsAuthError("no directory scope"))
    inject([ok, boom], {"a.example.edu", "b.example.edu"})
    out = server.suspended_accounts()["domains"]
    assert out["a.example.edu"]["count"] == 1
    assert "error" in out["b.example.edu"]  # one domain's failure does not sink the others


def test_suspended_accounts_unknown_domain_is_error(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    assert "error" in server.suspended_accounts(domain="nope.example")


_USER_RECORD = {
    "id": "112233445566778899000",
    "primaryEmail": "user@example.edu",
    "name": {"givenName": "A", "familyName": "B", "fullName": "A B"},
    "suspended": True,
    "suspensionReason": "ADMIN",
    "suspensionTime": "2026-06-01T09:00:00.000Z",
    "archived": False,
    "archivalTime": None,
    "lastLoginTime": "2026-05-30T01:02:03.000Z",
    "creationTime": "2019-04-01T00:00:00.000Z",
    "changePasswordAtNextLogin": False,
    "isEnrolledIn2Sv": False,
    "isEnforcedIn2Sv": True,
    "orgUnitPath": "/Students",
}


def test_get_user_projects_state_fields_and_resolves_domain_from_username(inject):
    # The tool exists to answer "why can't this person sign in", so every
    # field that answers it must survive projection -- an earlier per-user
    # tool (user_oauth_tokens) shows how easily a projection drops one.
    # Also guards suffix-based routing and that the full email reaches the
    # API as userKey, not just the local part.
    c = FakeDomainClient("example.edu", {}, user=_USER_RECORD)
    inject([c], {"example.edu"})
    out = server.get_user("user@example.edu")
    assert out["domain"] == "example.edu"
    assert out["found"] is True
    assert out["suspended"] is True
    assert out["suspension_reason"] == "ADMIN"
    assert out["suspension_time"] == "2026-06-01T09:00:00.000Z"
    assert out["archived"] is False
    assert out["last_login"] == "2026-05-30T01:02:03.000Z"
    assert out["created"] == "2019-04-01T00:00:00.000Z"
    assert out["change_password_at_next_login"] is False
    assert out["is_enrolled_in_2sv"] is False
    assert out["is_enforced_in_2sv"] is True
    assert out["org_unit"] == "/Students"
    assert out["id"] == "112233445566778899000"
    assert out["email"] == "user@example.edu"
    assert out["name"] == "A B"
    assert c.user_calls == ["user@example.edu"]  # full email passed through


def test_get_user_not_found_is_found_false_not_error(inject):
    # Issue #68's headline behaviour: an address that names no account is the
    # diagnostic ANSWER (typo, deleted account), not a failure. It must carry
    # found:false with no "error" key -- the smoke probe also depends on this,
    # since the harness fails any top-level error outright.
    c = FakeDomainClient("example.edu", {}, user=None)
    inject([c], {"example.edu"})
    out = server.get_user("ghost@example.edu")
    assert out["found"] is False
    assert "error" not in out
    assert out["domain"] == "example.edu"
    assert out["username"] == "ghost@example.edu"
    assert "suspended" not in out  # no state fields invented for an account that isn't there


def test_get_user_error_carries_no_found_key(inject):
    # The other half of the same distinction: a permission/transport failure
    # must never be reported as found:false, which would read as "this account
    # does not exist" and send an operator chasing a typo instead of a scope.
    from gwsadm_mcp.client import GwsAuthError

    inject([FakeDomainClient("example.edu", {}, user=GwsAuthError("no directory scope"))], {"example.edu"})
    out = server.get_user("user@example.edu")
    assert "error" in out
    assert "found" not in out
    assert out["domain"] == "example.edu"  # domain still identifiable even though the call failed


def test_get_user_absent_booleans_stay_none_not_false(inject):
    # A field Google omitted must stay unresolved. Coercing a missing
    # "suspended" to False would report a working account from a response that
    # never said so -- the same not-coerced rule group_delivery_policy keeps.
    inject([FakeDomainClient("example.edu", {}, user={"primaryEmail": "user@example.edu"})], {"example.edu"})
    out = server.get_user("user@example.edu")
    assert out["found"] is True
    assert out["suspended"] is None
    assert out["archived"] is None
    assert out["name"] is None  # the whole name object can be absent, not just fullName


def test_get_user_does_not_dump_the_raw_record(inject):
    # A Directory user record also carries phone numbers, recovery contacts
    # and custom schemas. The tool answers a sign-in question, so those must
    # not ride along into output an assistant will read back.
    record = dict(
        _USER_RECORD,
        recoveryPhone="+15550100",
        recoveryEmail="personal@example.invalid",
        customSchemas={"HR": {"employeeId": "E1234"}},
        thumbnailPhotoUrl="https://example.invalid/photo",
    )
    inject([FakeDomainClient("example.edu", {}, user=record)], {"example.edu"})
    out = server.get_user("user@example.edu")
    assert "recoveryPhone" not in out
    assert "recoveryEmail" not in out
    assert "customSchemas" not in out
    assert "thumbnailPhotoUrl" not in out


def test_get_user_unresolvable_domain_error_carries_username(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.get_user("user@nope.example")
    assert "error" in out
    assert out["username"] == "user@nope.example"  # errors always identify the request


def test_get_user_strips_whitespace(inject):
    # A pasted address often carries surrounding whitespace; the untrimmed
    # value would reach the API as an invalid userKey.
    c = FakeDomainClient("example.edu", {}, user=_USER_RECORD)
    inject([c], {"example.edu"})
    out = server.get_user("  user@example.edu  ")
    assert out["username"] == "user@example.edu"
    assert c.user_calls == ["user@example.edu"]  # not the untrimmed value


def test_get_user_explicit_domain_routes_alias_address(inject):
    # An alias/secondary-domain address has no [domain.*] section of its own;
    # the explicit domain param routes the lookup through the configured
    # section while the alias address passes through as userKey untouched.
    c = FakeDomainClient("example.edu", {}, user=_USER_RECORD)
    inject([c], {"example.edu"})
    out = server.get_user("user@alias.edu", domain="example.edu")
    assert "error" not in out
    assert out["domain"] == "example.edu"
    assert c.user_calls == ["user@alias.edu"]
    # The canonical address Google reports, not the alias that was asked about.
    assert out["email"] == "user@example.edu"


def test_get_user_rejects_non_email():
    # Validation fires before _clients(), so no client injection is needed —
    # a malformed input must never surface as a config error.
    out = server.get_user("not-an-email")
    assert "not an email address" in out["error"]


def test_get_user_rejects_empty_domain_part():
    # "user@" has an "@" but no domain; must be rejected as a malformed email,
    # not misdiagnosed as "unknown domain ''".
    out = server.get_user("user@")
    assert "not an email address" in out["error"]


def test_get_user_rejects_internal_whitespace(inject):
    # "user@ example.edu": the domain suffix would match config after a strip,
    # but the raw string is an invalid userKey — reject it instead of sending
    # it to the API and reporting a misleading "directory API error".
    c = FakeDomainClient("example.edu", {}, user=_USER_RECORD)
    inject([c], {"example.edu"})
    out = server.get_user("user@ example.edu")
    assert "not an email address" in out["error"]
    assert c.user_calls == []  # never reached the API


def test_user_oauth_tokens_projects_and_resolves_domain_from_username(inject):
    tokens = [
        {
            "clientId": "123.apps.googleusercontent.com",
            "displayText": "Some App",
            "scopes": ["https://mail.google.com/"],
            "anonymous": False,
            "nativeApp": False,
        }
    ]
    c = FakeDomainClient("example.edu", {}, tokens=tokens)
    inject([c], {"example.edu"})
    out = server.user_oauth_tokens("user@example.edu")
    assert out["domain"] == "example.edu"
    assert out["count"] == 1
    entry = out["tokens"][0]
    assert entry["client_id"] == "123.apps.googleusercontent.com"
    assert entry["scopes"] == ["https://mail.google.com/"]
    assert c.token_calls == ["user@example.edu"]  # full email passed through, not just the local part


def test_user_oauth_tokens_no_grants_is_empty_not_error(inject):
    inject([FakeDomainClient("example.edu", {}, tokens=[])], {"example.edu"})
    out = server.user_oauth_tokens("user@example.edu")
    assert out["count"] == 0
    assert out["tokens"] == []


def test_user_oauth_tokens_degrades_on_auth_error(inject):
    from gwsadm_mcp.client import GwsAuthError

    inject([FakeDomainClient("example.edu", {}, tokens=GwsAuthError("no security scope"))], {"example.edu"})
    out = server.user_oauth_tokens("user@example.edu")
    assert "error" in out
    assert out["domain"] == "example.edu"  # domain still identifiable even though the call failed


def test_user_oauth_tokens_unresolvable_domain_error_carries_username(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.user_oauth_tokens("user@nope.example")
    assert "error" in out
    assert out["username"] == "user@nope.example"  # errors always identify the request


def test_user_oauth_tokens_strips_whitespace(inject):
    c = FakeDomainClient("example.edu", {}, tokens=[])
    inject([c], {"example.edu"})
    out = server.user_oauth_tokens("  user@example.edu  ")
    assert out["username"] == "user@example.edu"
    assert c.token_calls == ["user@example.edu"]  # not the untrimmed value


def test_user_oauth_tokens_explicit_domain_routes_alias_address(inject):
    # An alias/secondary-domain address has no [domain.*] section of its own;
    # the explicit domain param routes the lookup through the configured
    # section while the alias address passes through as userKey untouched.
    c = FakeDomainClient("example.edu", {}, tokens=[])
    inject([c], {"example.edu"})
    out = server.user_oauth_tokens("user@alias.edu", domain="example.edu")
    assert "error" not in out
    assert out["domain"] == "example.edu"
    assert c.token_calls == ["user@alias.edu"]


def test_user_oauth_tokens_rejects_non_email():
    # Validation fires before _clients(), so no client injection is needed —
    # a malformed input must never surface as a config error.
    out = server.user_oauth_tokens("not-an-email")
    assert "not an email address" in out["error"]


def test_user_oauth_tokens_rejects_empty_domain_part():
    # "user@" has an "@" but no domain; must be rejected as a malformed email,
    # not misdiagnosed as "unknown domain ''".
    out = server.user_oauth_tokens("user@")
    assert "not an email address" in out["error"]


def test_user_oauth_tokens_rejects_internal_whitespace(inject):
    # "user@ example.edu": the domain suffix would match config after a strip,
    # but the raw string is an invalid userKey — reject it instead of sending
    # it to the API and reporting a misleading "directory API error".
    c = FakeDomainClient("example.edu", {}, tokens=[])
    inject([c], {"example.edu"})
    out = server.user_oauth_tokens("user@ example.edu")
    assert "not an email address" in out["error"]
    assert c.token_calls == []  # never reached the API


def test_gmail_message_trace_mixed_found_not_found_error(inject):
    found = {
        "label_ids": ["INBOX", "UNREAD"],
        "headers": {"Date": "Wed, 01 Jul 2026 00:00:00 +0900"},
        "internal_date": "1783000000000",
        "snippet": "hello",
        "match_count": 1,
        "match_count_capped": False,
    }
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        gmail_messages={
            "hit@example.edu": found,
            "miss@example.edu": None,
            "denied@example.edu": GwsAuthError("no gmail scope"),
        },
    )
    inject([c], {"example.edu"})
    out = server.gmail_message_trace("<abc@agent.smp.ne.jp>", "hit@example.edu, miss@example.edu, denied@example.edu")
    assert out["message_id"] == "abc@agent.smp.ne.jp"  # angle brackets stripped
    assert out["recipients_checked"] == 3
    assert out["found"] == 1
    assert out["not_found"] == 1
    assert out["errors"] == 1
    assert out["results"]["hit@example.edu"]["folder"] == "inbox"
    assert out["results"]["hit@example.edu"]["found"] is True
    assert "ambiguous" not in out["results"]["hit@example.edu"]
    assert out["results"]["miss@example.edu"] == {"domain": "example.edu", "found": False}
    assert "error" in out["results"]["denied@example.edu"]


def test_gmail_message_trace_flags_ambiguous_multi_match(inject):
    found = {
        "label_ids": ["INBOX"],
        "headers": {},
        "internal_date": "1",
        "snippet": "",
        "match_count": 2,
        "match_count_capped": False,
    }
    c = FakeDomainClient("example.edu", {}, gmail_messages={"hit@example.edu": found})
    inject([c], {"example.edu"})
    out = server.gmail_message_trace("abc@agent.smp.ne.jp", "hit@example.edu")
    result = out["results"]["hit@example.edu"]
    assert result["ambiguous"] is True
    assert result["match_count"] == 2
    assert "match_count_capped" not in result


def test_gmail_message_trace_flags_match_count_capped(inject):
    found = {
        "label_ids": ["INBOX"],
        "headers": {},
        "internal_date": "1",
        "snippet": "",
        "match_count": 5,
        "match_count_capped": True,
    }
    c = FakeDomainClient("example.edu", {}, gmail_messages={"hit@example.edu": found})
    inject([c], {"example.edu"})
    out = server.gmail_message_trace("abc@agent.smp.ne.jp", "hit@example.edu")
    result = out["results"]["hit@example.edu"]
    assert result["ambiguous"] is True
    assert result["match_count_capped"] is True


def test_gmail_message_trace_rejects_malformed_message_id(inject):
    c = FakeDomainClient("example.edu", {})
    inject([c], {"example.edu"})
    # Embedded whitespace could smuggle Gmail search syntax (e.g. "OR",
    # "from:...") into the rfc822msgid query -- rejected before any recipient
    # is even looked at.
    out = server.gmail_message_trace("abc@agent.example OR from:me", "user@example.edu")
    assert "error" in out
    assert "not a valid" in out["error"]
    assert c.gmail_calls == []


def test_gmail_message_trace_accepts_legitimate_atext_characters(inject):
    # RFC 5322 dot-atom-text allows "!#$%&'*+-/=?^_`{|}~" in a Message-ID's
    # local part, not just alnum/dot/underscore/percent/plus/hyphen -- a
    # real id using them (e.g. "/" and "=") must not be rejected as
    # malformed.
    c = FakeDomainClient("example.edu", {}, gmail_messages={"user@example.edu": None})
    inject([c], {"example.edu"})
    out = server.gmail_message_trace("<abc/def=123@example.edu>", "user@example.edu")
    assert "error" not in out
    assert out["message_id"] == "abc/def=123@example.edu"
    assert c.gmail_calls == [("user@example.edu", "abc/def=123@example.edu")]


def test_gmail_message_trace_folder_classification():
    trash = {"label_ids": ["TRASH"], "headers": {}, "internal_date": "1", "snippet": ""}
    spam = {"label_ids": ["SPAM", "UNREAD"], "headers": {}, "internal_date": "1", "snippet": ""}
    archived = {"label_ids": ["UNREAD"], "headers": {}, "internal_date": "1", "snippet": ""}
    assert server._classify_folder(trash["label_ids"]) == "trash"
    assert server._classify_folder(spam["label_ids"]) == "spam"
    assert server._classify_folder(archived["label_ids"]) == "archived"


def test_gmail_message_trace_rejects_over_limit_recipients(inject):
    c = FakeDomainClient("example.edu", {})
    inject([c], {"example.edu"})
    addrs = " ".join(f"u{i}@example.edu" for i in range(server.MAX_TRACE_RECIPIENTS + 1))
    out = server.gmail_message_trace("id@example.invalid", addrs)
    assert "error" in out
    assert "exceeds" in out["error"]
    assert c.gmail_calls == []  # rejected before any per-recipient work


def test_gmail_message_trace_rejects_empty_recipients(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.gmail_message_trace("id@example.invalid", "   ")
    assert out["error"] == "no recipients given"


def test_gmail_message_trace_parses_comma_and_whitespace_and_dedupes():
    addrs = server._parse_recipients("a@example.edu, b@example.edu\n a@example.edu\tc@example.edu")
    assert addrs == ["a@example.edu", "b@example.edu", "c@example.edu"]


def test_gmail_message_trace_dedupes_recipients_case_insensitively():
    # Gmail treats an address's casing as insignificant; a caller pasting a
    # mixed-case duplicate must not double the per-recipient API work or
    # inflate recipients_checked/found/not_found for what is one mailbox.
    addrs = server._parse_recipients("User@Example.com, user@example.com")
    assert addrs == ["User@Example.com"]  # first-seen casing kept


def test_gmail_message_trace_routes_mixed_domain_recipients_by_suffix(inject):
    staff = FakeDomainClient("example.edu", {}, gmail_messages={"a@example.edu": None})
    students = FakeDomainClient("students.example.edu", {}, gmail_messages={"b@students.example.edu": None})
    inject([staff, students], {"example.edu", "students.example.edu"})
    out = server.gmail_message_trace("id@example.invalid", "a@example.edu b@students.example.edu")
    assert out["results"]["a@example.edu"]["domain"] == "example.edu"
    assert out["results"]["b@students.example.edu"]["domain"] == "students.example.edu"
    assert staff.gmail_calls == [("a@example.edu", "id@example.invalid")]
    assert students.gmail_calls == [("b@students.example.edu", "id@example.invalid")]


def test_gmail_message_trace_explicit_domain_overrides_per_recipient_resolution(inject):
    # An alias/secondary-domain recipient has no [domain.*] section of its
    # own; the explicit domain param routes it through the configured
    # section instead of the unresolvable suffix.
    c = FakeDomainClient("example.edu", {}, gmail_messages={"user@alias.edu": None})
    inject([c], {"example.edu"})
    out = server.gmail_message_trace("id@example.invalid", "user@alias.edu", domain="example.edu")
    assert out["results"]["user@alias.edu"] == {"domain": "example.edu", "found": False}


def test_gmail_message_trace_unresolvable_domain_is_per_recipient_error(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.gmail_message_trace("id@example.invalid", "user@nope.example")
    assert "error" in out["results"]["user@nope.example"]
    assert out["errors"] == 1


def test_group_delivery_policy_resolves_domain_and_returns_policy(inject):
    policy = {
        "who_can_post": "ALL_IN_DOMAIN_CAN_POST",
        "allow_external_members": False,
        "is_archived": False,
        "message_moderation_level": "MODERATE_NONE",
        "spam_moderation_level": "MODERATE",
        "allow_web_posting": True,
    }
    c = FakeDomainClient("example.edu", {}, group_settings={"team@example.edu": policy})
    inject([c], {"example.edu"})
    out = server.group_delivery_policy("team@example.edu")
    assert out["domain"] == "example.edu"
    assert out["group_email"] == "team@example.edu"
    assert out["found"] is True
    assert out["who_can_post"] == "ALL_IN_DOMAIN_CAN_POST"
    assert out["allow_external_members"] is False
    assert c.group_settings_calls == ["team@example.edu"]


def test_group_delivery_policy_not_found_is_not_an_error(inject):
    # None from the client means a plain HTTP 404 -- the address is not a
    # group in this domain, a normal answer distinguished from a real error.
    c = FakeDomainClient("example.edu", {}, group_settings={"nonexistent@example.edu": None})
    inject([c], {"example.edu"})
    out = server.group_delivery_policy("nonexistent@example.edu")
    assert "error" not in out
    assert out["found"] is False
    assert out["domain"] == "example.edu"


def test_group_delivery_policy_degrades_on_auth_error(inject):
    from gwsadm_mcp.client import GwsAuthError

    inject(
        [FakeDomainClient("example.edu", {}, group_settings=GwsAuthError("no groups.settings scope"))],
        {"example.edu"},
    )
    out = server.group_delivery_policy("team@example.edu")
    assert "error" in out
    assert out["domain"] == "example.edu"  # domain still identifiable even though the call failed


def test_group_delivery_policy_unresolvable_domain_error_carries_group_email(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.group_delivery_policy("team@nope.example")
    assert "error" in out
    assert out["group_email"] == "team@nope.example"


def test_group_delivery_policy_strips_whitespace(inject):
    c = FakeDomainClient("example.edu", {}, group_settings={"team@example.edu": {}})
    inject([c], {"example.edu"})
    out = server.group_delivery_policy("  team@example.edu  ")
    assert out["group_email"] == "team@example.edu"
    assert c.group_settings_calls == ["team@example.edu"]  # not the untrimmed value


def test_group_delivery_policy_explicit_domain_routes_alias_address(inject):
    c = FakeDomainClient("example.edu", {}, group_settings={"team@alias.edu": {}})
    inject([c], {"example.edu"})
    out = server.group_delivery_policy("team@alias.edu", domain="example.edu")
    assert "error" not in out
    assert out["domain"] == "example.edu"
    assert c.group_settings_calls == ["team@alias.edu"]


def test_group_delivery_policy_rejects_non_email():
    out = server.group_delivery_policy("not-an-email")
    assert "not an email address" in out["error"]


def test_list_group_members_returns_group_and_members(inject):
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"team@example.edu": {"email": "team@example.edu", "name": "Team"}},
        group_members={"team@example.edu": ([{"email": "a@example.edu", "role": "MEMBER"}], False)},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert out["domain"] == "example.edu"
    assert out["group_email"] == "team@example.edu"
    assert out["group"] == {"email": "team@example.edu", "name": "Team"}
    assert out["member_count"] == 1
    assert out["members"] == [{"email": "a@example.edu", "role": "MEMBER"}]
    assert out["capped"] is False
    assert c.group_meta_calls == ["team@example.edu"]
    assert c.group_members_calls == [("team@example.edu", 20)]  # default max_pages


def test_list_group_members_passes_max_pages_and_surfaces_capped(inject):
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"team@example.edu": {}},
        group_members={"team@example.edu": ([], True)},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu", max_pages=3)
    assert out["capped"] is True
    assert c.group_members_calls == [("team@example.edu", 3)]


def test_list_group_members_degrades_to_group_only_when_only_member_scope_missing(inject):
    # Only admin.directory.group.member.readonly is missing -- the group
    # metadata (a DIFFERENT, independently-granted scope) must still come
    # through rather than the whole call failing.
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"team@example.edu": {"email": "team@example.edu"}},
        group_members=GwsAuthError("no group.member.readonly scope"),
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert "error" not in out
    assert out["group"] == {"email": "team@example.edu"}
    assert out["members"] == []
    assert out["member_count"] == 0
    # capped=True here means "coverage incomplete", not "confirmed empty" --
    # a failed lookup and a genuinely empty group must not look identical.
    assert out["capped"] is True
    assert "members_error" in out


def test_list_group_members_degrades_to_members_only_when_only_group_scope_missing(inject):
    # The mirror case: admin.directory.group.readonly is missing but
    # admin.directory.group.member.readonly is granted -- the roster must
    # still come through, with the group section reporting its own error.
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta=GwsAuthError("no group.readonly scope"),
        group_members={"team@example.edu": ([{"email": "a@example.edu"}], False)},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert "error" not in out
    assert "error" in out["group"]
    assert out["members"] == [{"email": "a@example.edu"}]
    assert out["member_count"] == 1


def test_list_group_members_not_found_when_both_agree_with_no_error(inject):
    # get_group and list_group_members both returning None (a plain 404, no
    # exception) means this address isn't a group at all -- a clean answer,
    # not a partial-coverage state, so it gets its own found:false shape
    # rather than an empty group/members pair indistinguishable from a real
    # group with zero members.
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"nonexistent@example.edu": None},
        group_members={"nonexistent@example.edu": None},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("nonexistent@example.edu")
    assert "error" not in out
    assert out["found"] is False
    assert "group" not in out
    assert "members" not in out


def test_list_group_members_confirmed_not_found_wins_over_unrelated_group_error(inject):
    # get_group fails (e.g. its own scope missing) but list_group_members
    # independently CONFIRMS not-found (a 404, no exception) -- that
    # confirmation is stronger evidence than an unrelated failure on the
    # OTHER scope and must not be buried under a generic {"error": ...}.
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta=GwsAuthError("no group.readonly scope"),
        group_members={"nonexistent@example.edu": None},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("nonexistent@example.edu")
    assert "error" not in out
    assert out["found"] is False
    assert "group.readonly" in out["group_lookup_error"]
    assert "group" not in out
    assert "members" not in out


def test_list_group_members_confirmed_not_found_wins_over_unrelated_members_error(inject):
    # Mirror of the above: list_group_members fails (e.g. its own scope
    # missing) but get_group independently CONFIRMS not-found.
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"nonexistent@example.edu": None},
        group_members=GwsAuthError("no group.member.readonly scope"),
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("nonexistent@example.edu")
    assert "error" not in out
    assert out["found"] is False
    assert "group.member.readonly" in out["members_lookup_error"]
    assert "group" not in out
    assert "members" not in out
    # Same coverage-contract marker every other incomplete-member-lookup
    # response carries, so a caller checking one field needs no special case.
    assert out["capped"] is True


def test_list_group_members_group_not_found_but_members_found_is_not_top_level_not_found(inject):
    # Mixed state: get_group says not-found (no error) but list_group_members
    # DOES find members -- inconsistent, but must not be misreported as a
    # clean top-level found:false (that requires BOTH sides to agree).
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"team@example.edu": None},
        group_members={"team@example.edu": ([{"email": "a@example.edu"}], False)},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert "error" not in out
    assert "found" not in out  # not the clean both-sides-agree shape
    assert out["group"] == {"found": False}
    assert out["members"] == [{"email": "a@example.edu"}]


def test_list_group_members_member_not_found_when_group_exists_is_not_a_confirmed_empty_roster(inject):
    # Mirror of the above: get_group DOES find the group, but the member
    # lookup independently returns not-found (no exception) -- e.g. the
    # group was deleted between the two calls. This must not be reported as
    # a confirmed-empty roster (member_count=0, capped=False looks IDENTICAL
    # to a real, existing, genuinely-empty group without this check).
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta={"team@example.edu": {"email": "team@example.edu"}},
        group_members={"team@example.edu": None},
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert "error" not in out
    assert "found" not in out  # not the clean both-sides-agree shape (group WAS found)
    assert out["group"] == {"email": "team@example.edu"}
    assert out["members"] == []
    assert out["member_count"] == 0
    assert out["capped"] is True  # coverage incomplete, not "confirmed zero"
    assert "members_error" in out


def test_list_group_members_top_level_error_only_when_both_scopes_fail(inject):
    from gwsadm_mcp.client import GwsAuthError

    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta=GwsAuthError("no group.readonly scope"),
        group_members=GwsAuthError("no group.member.readonly scope"),
    )
    inject([c], {"example.edu"})
    out = server.list_group_members("team@example.edu")
    assert "error" in out
    assert out["domain"] == "example.edu"
    assert "group" not in out  # a single combined error, not two redundant per-section ones


def test_list_group_members_calls_both_independently_regardless_of_order(inject):
    # Both get_group and list_group_members must always be attempted, even
    # when one is guaranteed to fail -- neither call may gate the other,
    # since they exercise two separately-granted DWD scopes.
    c = FakeDomainClient(
        "example.edu",
        {},
        group_meta=GwsError("[example.edu] directory API error (groups.get): HTTP 404"),
        group_members={"team@example.edu": ([{"email": "a@example.edu"}], False)},
    )
    inject([c], {"example.edu"})
    server.list_group_members("team@example.edu")
    assert c.group_meta_calls == ["team@example.edu"]
    assert c.group_members_calls == [("team@example.edu", 20)]


def test_list_group_members_unresolvable_domain_error_carries_group_email(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    out = server.list_group_members("team@nope.example")
    assert "error" in out
    assert out["group_email"] == "team@nope.example"


def test_list_group_members_rejects_non_email():
    out = server.list_group_members("not-an-email")
    assert "not an email address" in out["error"]


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
    drive_pages = {mp for app, _, mp, _f in client.calls if app == "drive"}
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
    drive_pages = {mp for app, _, mp, _f in client.calls if app == "drive"}
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


# --- GWSADM_MAX_WORKERS parsing: a documented tuning knob must never crash startup ---


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, 8),  # unset -> default
        ("", 8),  # empty -> default (not a crash)
        ("foo", 8),  # non-integer -> default (not a crash)
        ("1", 1),
        ("16", 16),
        ("0", 1),  # clamped up
        ("-3", 1),  # clamped up
        ("999", 32),  # clamped down
    ],
)
def test_max_workers_parsing_is_robust(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("GWSADM_MAX_WORKERS", raising=False)
    else:
        monkeypatch.setenv("GWSADM_MAX_WORKERS", value)
    assert server._max_workers() == expected


def test_server_imports_with_bad_max_workers(monkeypatch):
    """A garbage GWSADM_MAX_WORKERS must not take the stdio server down at startup."""
    monkeypatch.setenv("GWSADM_MAX_WORKERS", "not-a-number")
    # _max_workers() is what _parallel_fetch calls; it must degrade to the default.
    assert server._max_workers() == 8


def test_timeout_probe_steps_and_reports_missing_token(monkeypatch):
    """timeout_probe walks `seconds` in ~5s steps and reports progressToken absence.

    Sleeps are stubbed so the unit test is instant; the real-time behaviour is what the
    end-to-end connector run exercises (issue #10)."""
    import asyncio

    async def _noop(_):  # avoid real sleeping in the unit test
        return None

    monkeypatch.setattr(server.asyncio, "sleep", _noop)
    out = asyncio.run(server.timeout_probe(seconds=12, emit_progress=False, ctx=None))
    assert out["requested_seconds"] == 12
    assert out["slept_seconds"] == 12
    assert out["steps"] == 3  # 5 + 5 + 2
    assert out["emit_progress"] is False
    assert out["progress_token_present"] is False  # no ctx -> no progressToken


def test_timeout_probe_clamps_adversarial_seconds(monkeypatch):
    """An LLM-driven `seconds` can't tie up the server: clamped to 0..600, raw echoed."""
    import asyncio

    async def _noop(_):
        return None

    monkeypatch.setattr(server.asyncio, "sleep", _noop)

    big = asyncio.run(server.timeout_probe(seconds=100_000, emit_progress=False, ctx=None))
    assert big["requested_seconds"] == 100_000
    assert big["slept_seconds"] == server._PROBE_MAX_SECONDS  # clamped down to 600
    assert big["steps"] == server._PROBE_MAX_SECONDS // server._PROBE_STEP_SECONDS  # 120

    neg = asyncio.run(server.timeout_probe(seconds=-5, emit_progress=False, ctx=None))
    assert neg["requested_seconds"] == -5
    assert neg["slept_seconds"] == 0 and neg["steps"] == 0  # negative clamped to 0, no sleeping


def _fake_ctx(progress_token):
    """Minimal stand-in for FastMCP's Context: exposes request_context.meta.progressToken and an
    async report_progress that records its calls. (Real report_progress no-ops without a token, but
    the probe calls it unconditionally — FastMCP does the gating, so the probe must not.)"""
    import types

    calls: list = []

    async def _report_progress(progress, total=None, message=None):
        calls.append({"progress": progress, "total": total, "message": message})

    meta = types.SimpleNamespace(progressToken=progress_token)
    ctx = types.SimpleNamespace(request_context=types.SimpleNamespace(meta=meta), report_progress=_report_progress)
    ctx.calls = calls
    return ctx


def test_timeout_probe_emits_progress_per_step_with_token(monkeypatch):
    """The emit path (the tool's whole reason to exist): with a progressToken, report_progress fires
    once per step with increasing progress, and progress_token_present is True."""
    import asyncio

    async def _noop(_):
        return None

    monkeypatch.setattr(server.asyncio, "sleep", _noop)
    ctx = _fake_ctx("tok-1")
    out = asyncio.run(server.timeout_probe(seconds=12, emit_progress=True, ctx=ctx))
    assert out["progress_token_present"] is True
    assert out["steps"] == 3
    assert len(ctx.calls) == 3  # one notification per step
    assert [c["progress"] for c in ctx.calls] == [5, 10, 12]  # elapsed after each step, monotonic
    assert all(c["total"] == 12 for c in ctx.calls)


def test_timeout_probe_absent_token_still_emits(monkeypatch):
    """A non-None ctx whose meta carries no token: progress_token_present is False, yet the probe
    still calls report_progress (the probe never gates on the token — FastMCP no-ops it)."""
    import asyncio

    async def _noop(_):
        return None

    monkeypatch.setattr(server.asyncio, "sleep", _noop)
    ctx = _fake_ctx(None)  # meta present, progressToken is None
    out = asyncio.run(server.timeout_probe(seconds=5, emit_progress=True, ctx=ctx))
    assert out["progress_token_present"] is False
    assert len(ctx.calls) == 1  # still emitted; a real client without a token would just get a no-op


# --- daily_brief background job + poll ---


def _await_job(job_id, timeout=5.0):
    """Poll daily_brief_result until the job leaves 'running' (jobs finish in ms with FakeDomainClient)."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = server.daily_brief_result(job_id)
        if r["status"] != "running":
            return r
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_daily_brief_start_and_result_completes(inject):
    server._JOBS.clear()
    canned = {("login", "suspicious_login"): ([_item("x@e.edu", "suspicious_login")], False)}
    inject([FakeDomainClient("e.edu", canned)], {"e.edu"})

    start = server.daily_brief_start(hours=24)
    assert start["status"] == "running"
    assert start["poll_with"] == "daily_brief_result"
    assert isinstance(start.get("job_id"), str) and start["job_id"]

    res = _await_job(start["job_id"])
    assert res["status"] == "done"
    # result is byte-for-byte the synchronous daily_brief payload
    assert res["result"]["window_hours"] == 24
    assert "e.edu" in res["result"]["summary"]
    assert res["result"]["summary"]["e.edu"]["suspicious_logins"] == 1


def test_daily_brief_result_unknown_job():
    server._JOBS.clear()
    out = server.daily_brief_result("deadbeef")
    assert out == {"job_id": "deadbeef", "status": "unknown"}


def test_daily_brief_start_config_error(monkeypatch):
    server._JOBS.clear()
    monkeypatch.setitem(server._state, "clients", None)  # force _clients() to re-run load_config
    monkeypatch.setattr(server, "load_config", lambda: (_ for _ in ()).throw(server.ConfigError("boom")))
    out = server.daily_brief_start()
    assert "error" in out and "boom" in out["error"]
    assert "job_id" not in out  # no job spawned on a config error


def test_daily_brief_job_captures_worker_error(inject, monkeypatch):
    server._JOBS.clear()
    inject([FakeDomainClient("e.edu", {})], {"e.edu"})

    # A crash inside the background worker must surface as the job's error, not vanish —
    # and only the exception TYPE, never its (potentially sensitive/large) message.
    def _boom(*a, **k):
        raise RuntimeError("secret /etc/key path")

    monkeypatch.setattr(server, "_login_audit", _boom)
    start = server.daily_brief_start()
    res = _await_job(start["job_id"])
    assert res["status"] == "error"
    assert res["error"] == "RuntimeError"  # type only; the message must not leak
    assert "secret" not in res["error"] and "/etc/" not in res["error"]


def test_daily_brief_result_reaps_expired_job(inject):
    server._JOBS.clear()
    inject([FakeDomainClient("e.edu", {})], {"e.edu"})
    # A job whose result has been retained past the TTL (finished long ago) is reaped on poll
    # (not only on the next start), so its payload is freed and an expired id resolves to "unknown".
    import time

    now = time.monotonic()
    with server._JOBS_LOCK:
        server._JOBS["stale"] = {
            "status": "done",
            "result": {"big": "x"},
            "created": now - 999,
            "finished": now - server._JOB_TTL_SECONDS - 1,  # retained past the TTL
        }
    out = server.daily_brief_result("stale")
    assert out == {"job_id": "stale", "status": "unknown"}
    assert "stale" not in server._JOBS  # reaped, memory freed


def test_daily_brief_long_run_result_is_retained(inject):
    """The TTL is measured from completion, not start: a brief that itself ran longer than the
    TTL must still be retrievable for a full TTL window afterward (the regression from the
    start-time-anchored reap that lost long-brief results)."""
    server._JOBS.clear()
    inject([FakeDomainClient("e.edu", {})], {"e.edu"})
    import time

    now = time.monotonic()
    with server._JOBS_LOCK:
        server._JOBS["long"] = {
            "status": "done",
            "result": {"window_hours": 24},
            "created": now - 10_000,  # started ages ago (a very long run)
            "finished": now - 1,  # but only just finished
        }
    out = server.daily_brief_result("long")
    assert out["status"] == "done"  # NOT reaped despite a huge created-age
    assert out["result"] == {"window_hours": 24}
    assert "long" in server._JOBS


def test_daily_brief_start_thread_failure_leaves_no_zombie(inject, monkeypatch):
    """If the worker thread can't start, the just-inserted 'running' entry must not leak as an
    unreapable zombie (running jobs are never reaped)."""
    server._JOBS.clear()
    inject([FakeDomainClient("e.edu", {})], {"e.edu"})

    class _NoStartThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(server.threading, "Thread", _NoStartThread)
    out = server.daily_brief_start()
    assert out["status"] == "error" and out["error"] == "RuntimeError"
    assert out == {"status": "error", "error": "RuntimeError"}
    assert server._JOBS == {}  # no leftover running job


def test_daily_brief_start_rejects_when_over_cap(inject, monkeypatch):
    server._JOBS.clear()
    inject([FakeDomainClient("e.edu", {})], {"e.edu"})
    # Fill the registry to the cap with in-flight jobs, then a fresh start is rejected.
    monkeypatch.setattr(server, "_JOBS_MAX", 3)
    import time

    with server._JOBS_LOCK:
        for i in range(3):
            server._JOBS[f"j{i}"] = {"status": "running", "created": time.monotonic()}
    out = server.daily_brief_start()
    assert out["status"] == "rejected"
    assert "job_id" not in out
    server._JOBS.clear()


# --- drive_doc_activity ---

DOC = "1AbCdEfGhIjKlMnOpQrStUvWx"


def _doc_items():
    return [
        _item(
            "ext@gmail.com",
            "change_user_access",
            {
                "target_user": "Partner@corp.example",
                "new_value": ["can_edit"],
                "owner": "drive_Lab",
                "doc_title": "quote.pdf",
                "doc_id": DOC,
            },
            time="2026-07-02T00:00:00.000Z",
        ),
        _item(
            "ext@gmail.com",
            "create",
            {"owner": "drive_Lab", "doc_title": "quote.pdf", "doc_id": DOC},
            time="2026-07-01T00:00:00.000Z",
        ),
        _item("viewer@example.edu", "view", {"doc_id": DOC}, time="2026-07-01T12:00:00.000Z"),
    ]


def test_drive_doc_activity_reconstructs_history(inject):
    client = FakeDomainClient("example.edu", {("drive", f"doc_id=={DOC}"): (_doc_items(), False)})
    inject([client], {"example.edu"})
    out = server.drive_doc_activity(DOC)
    dom = out["domains"]["example.edu"]
    assert dom["owner"] == "drive_Lab"  # a shared drive name, not a user address
    assert dom["doc_title"] == "quote.pdf"
    assert dom["event_counts"] == {"change_user_access": 1, "create": 1, "view": 1}
    assert [e["event"] for e in dom["events"]] == ["change_user_access", "create"]  # view counted, not listed
    assert dom["events"][0]["target_user"] == "partner@corp.example"  # normalized like the sharing tool
    assert dom["events_truncated"] is False and dom["capped"] is False
    # The fetch itself was doc-scoped server-side, not a full-window scan.
    assert ("drive", None, 5, f"doc_id=={DOC}") in client.calls


def test_drive_doc_activity_rejects_malformed_doc_id(inject):
    client = FakeDomainClient("example.edu", {})
    inject([client], {"example.edu"})
    # A comma/operator would change the meaning of the filters expression.
    out = server.drive_doc_activity("abc,doc_id==other0000")
    assert "error" in out
    assert client.calls == []  # rejected before any API traffic


def test_drive_doc_activity_truncates_listing_but_not_counts(inject):
    client = FakeDomainClient("example.edu", {("drive", f"doc_id=={DOC}"): (_doc_items(), True)})
    inject([client], {"example.edu"})
    dom = server.drive_doc_activity(DOC, max_events=1)["domains"]["example.edu"]
    assert len(dom["events"]) == 1
    assert dom["events_truncated"] is True
    assert dom["event_counts"]["create"] == 1  # counts still cover everything fetched
    assert dom["capped"] is True  # pagination cap surfaced unchanged


def test_drive_doc_activity_degrades_per_domain(inject):
    from gwsadm_mcp.client import GwsAuthError

    ok = FakeDomainClient("a.example.edu", {("drive", f"doc_id=={DOC}"): (_doc_items(), False)})
    boom = FakeDomainClient("b.example.edu", {("drive", f"doc_id=={DOC}"): GwsAuthError("auth failed")})
    inject([ok, boom], {"a.example.edu", "b.example.edu"})
    out = server.drive_doc_activity(DOC)["domains"]
    assert out["a.example.edu"]["owner"] == "drive_Lab"
    assert "error" in out["b.example.edu"]  # one tenant's failure does not sink the other


def test_drive_doc_activity_unknown_domain_is_error(inject):
    inject([FakeDomainClient("example.edu", {})], {"example.edu"})
    assert "error" in server.drive_doc_activity(DOC, domain="nope.example")


# --- shared_drive_membership_changes ---


def _membership_items():
    return [
        _item(
            "prof@example.edu",
            "shared_drive_membership_change",
            {
                "owner": "drive_Lab",
                "target_user": "Ext@gmail.com",
                "membership_change_type": "add_to_shared_drive",
            },
        ),
        _item(
            "prof@example.edu",
            "shared_drive_membership_change",
            {
                "owner": "OtherDrive",
                "target_user": "s1@example.edu",
                "membership_change_type": "change_roles",
            },
        ),
    ]


def test_shared_drive_membership_changes_classifies_targets(inject):
    client = FakeDomainClient(
        "example.edu", {("drive", "shared_drive_membership_change"): (_membership_items(), False)}
    )
    inject([client], {"example.edu"})
    dom = server.shared_drive_membership_changes()["domains"]["example.edu"]
    assert dom["total"] == 2
    ext, internal = dom["entries"]
    assert ext["drive"] == "drive_Lab"
    assert ext["target_user"] == "ext@gmail.com"
    assert ext["target_is_external"] is True
    assert ext["membership_change_type"] == "add_to_shared_drive"
    assert internal["target_is_external"] is False


def test_shared_drive_membership_changes_drive_name_narrows_listing(inject):
    client = FakeDomainClient("example.edu", {("drive", "shared_drive_membership_change"): (_membership_items(), True)})
    inject([client], {"example.edu"})
    dom = server.shared_drive_membership_changes(drive_name="lab")["domains"]["example.edu"]
    assert dom["total"] == 1  # case-insensitive substring on the drive name
    assert dom["entries"][0]["drive"] == "drive_Lab"
    assert dom["capped"] is True  # scan-level cap unrelated to the name filter


def test_shared_drive_membership_changes_truncates_listing_but_not_total(inject):
    client = FakeDomainClient(
        "example.edu", {("drive", "shared_drive_membership_change"): (_membership_items(), False)}
    )
    inject([client], {"example.edu"})
    dom = server.shared_drive_membership_changes(max_events=1)["domains"]["example.edu"]
    assert dom["total"] == 2
    assert len(dom["entries"]) == 1
    assert dom["events_truncated"] is True


def test_shared_drive_membership_changes_degrades_per_domain(inject):
    ok = FakeDomainClient("a.example.edu", {("drive", "shared_drive_membership_change"): (_membership_items(), False)})
    boom = FakeDomainClient("b.example.edu", {("drive", "shared_drive_membership_change"): GwsError("boom")})
    inject([ok, boom], {"a.example.edu", "b.example.edu"})
    out = server.shared_drive_membership_changes()["domains"]
    assert out["a.example.edu"]["total"] == 2
    assert "error" in out["b.example.edu"]


def test_drive_doc_activity_sibling_events_do_not_contaminate(inject):
    # One activity item can carry events for OTHER documents (a multi-file
    # share is one activity, one event per file). The sibling — listed FIRST,
    # with its own owner/title — must not leak into this doc's history.
    item = {
        "id": {"time": "2026-07-03T00:00:00.000Z"},
        "actor": {"email": "u@example.edu"},
        "events": [
            {
                "name": "change_user_access",
                "parameters": [
                    {"name": "doc_id", "value": "0OtherDocId000000000"},
                    {"name": "owner", "value": "someone.else@example.edu"},
                    {"name": "doc_title", "value": "other.pdf"},
                    {"name": "target_user", "value": "x@gmail.com"},
                ],
            },
            {
                "name": "change_user_access",
                "parameters": [
                    {"name": "doc_id", "value": DOC},
                    {"name": "owner", "value": "drive_Lab"},
                    {"name": "doc_title", "value": "quote.pdf"},
                    {"name": "target_user", "value": "y@gmail.com"},
                ],
            },
            {"name": "view", "parameters": []},  # no doc_id at all: unattributable
        ],
    }
    client = FakeDomainClient("example.edu", {("drive", f"doc_id=={DOC}"): ([item], False)})
    inject([client], {"example.edu"})
    dom = server.drive_doc_activity(DOC)["domains"]["example.edu"]
    assert dom["owner"] == "drive_Lab"  # not the sibling's owner
    assert dom["doc_title"] == "quote.pdf"
    assert dom["event_counts"] == {"change_user_access": 1}
    assert [e["target_user"] for e in dom["events"]] == ["y@gmail.com"]
    assert dom["sibling_events_skipped"] == 2  # other doc + unattributable


def test_shared_drive_membership_missing_drive_name_is_surfaced(inject):
    nameless = _item(
        "prof@example.edu",
        "shared_drive_membership_change",
        {"target_user": "ext@gmail.com", "membership_change_type": "add_to_shared_drive"},
    )
    client = FakeDomainClient(
        "example.edu",
        {("drive", "shared_drive_membership_change"): (_membership_items() + [nameless], False)},
    )
    inject([client], {"example.edu"})
    # With a name filter the nameless event can't be judged: dropped but counted.
    dom = server.shared_drive_membership_changes(drive_name="lab")["domains"]["example.edu"]
    assert dom["total"] == 1
    assert dom["missing_drive_name"] == 1
    # Without a filter it is listed normally with drive=None.
    dom = server.shared_drive_membership_changes()["domains"]["example.edu"]
    assert dom["total"] == 3
    assert dom["missing_drive_name"] == 0
    assert any(e["drive"] is None for e in dom["entries"])
