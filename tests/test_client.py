"""Tests for DomainClient (paging, capped flag, error mapping, param flattening)."""

import httplib2
import pytest
from googleapiclient.errors import HttpError

import gwsadm_mcp.client as client
from gwsadm_mcp.client import DomainClient, GwsError, event_parameters
from gwsadm_mcp.config import DomainConfig

CFG = DomainConfig("example.edu", "/tmp/sa.json", "audit-admin@example.edu", "C0abc")


class _Req:
    def __init__(self, resp, exc=None):
        self._resp, self._exc = resp, exc

    def execute(self, http=None):
        if self._exc:
            raise self._exc
        return self._resp


class FakeActivities:
    def __init__(self, pages, exc=None):
        self.pages, self.exc, self.calls = pages, exc, []

    def list(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req(self.pages[min(len(self.calls) - 1, len(self.pages) - 1)])


class FakeReports:
    def __init__(self, pages, exc=None):
        self._a = FakeActivities(pages, exc)

    def activities(self):
        return self._a


def _client(pages, exc=None):
    svc = FakeReports(pages, exc)
    return DomainClient(CFG, reports_service=svc), svc._a


class FakeUsers:
    def __init__(self, pages, exc=None):
        self.pages, self.exc, self.calls = pages, exc, []

    def list(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req(self.pages[min(len(self.calls) - 1, len(self.pages) - 1)])


class FakeDirectory:
    def __init__(self, pages, exc=None):
        self._u = FakeUsers(pages, exc)

    def users(self):
        return self._u


def _dir_client(pages, exc=None):
    svc = FakeDirectory(pages, exc)
    return DomainClient(CFG, directory_service=svc), svc._u


def test_fetch_activities_paginates_and_passes_params():
    import datetime

    c, a = _client(
        [
            {"items": [{"id": {"time": "t1"}}], "nextPageToken": "tok"},
            {"items": [{"id": {"time": "t2"}}]},
        ]
    )
    start = datetime.datetime(2026, 7, 1, tzinfo=datetime.timezone.utc)
    items, capped = c.fetch_activities("login", start=start, event_name="login_failure")
    assert len(items) == 2 and capped is False
    assert a.calls[0]["eventName"] == "login_failure"
    assert a.calls[0]["applicationName"] == "login"
    assert a.calls[0]["customerId"] == "C0abc"
    assert a.calls[0]["startTime"].startswith("2026-07-01T00:00:00")
    assert a.calls[1]["pageToken"] == "tok"


def test_fetch_activities_caps_pages():
    import datetime

    c, _ = _client([{"items": [{}], "nextPageToken": "more"}] * 5)
    items, capped = c.fetch_activities("drive", start=datetime.datetime.now(datetime.timezone.utc), max_pages=2)
    assert len(items) == 2 and capped is True  # stopped early with pages remaining


def test_list_suspended_users_paginates_and_passes_params():
    c, u = _dir_client(
        [
            {"users": [{"primaryEmail": "a@example.edu"}], "nextPageToken": "tok"},
            {"users": [{"primaryEmail": "b@example.edu"}]},
        ]
    )
    users, capped = c.list_suspended_users()
    assert len(users) == 2 and capped is False
    assert u.calls[0]["domain"] == "example.edu"
    assert u.calls[0]["query"] == "isSuspended=true"
    assert u.calls[1]["pageToken"] == "tok"


def test_list_suspended_users_caps_pages():
    c, _ = _dir_client([{"users": [{}], "nextPageToken": "more"}] * 5)
    users, capped = c.list_suspended_users(max_pages=2)
    assert len(users) == 2 and capped is True  # stopped early with pages remaining


def test_list_suspended_users_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _dir_client([], exc=err)
    with pytest.raises(GwsError):
        c.list_suspended_users()


class FakeTokens:
    def __init__(self, resp, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def list(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req(self.resp)


class FakeDirectorySecurity:
    def __init__(self, resp, exc=None):
        self._t = FakeTokens(resp, exc)

    def tokens(self):
        return self._t


def _sec_client(resp, exc=None):
    svc = FakeDirectorySecurity(resp, exc)
    return DomainClient(CFG, directory_security_service=svc), svc._t


def test_list_user_oauth_tokens_returns_items_and_passes_user_key():
    c, t = _sec_client({"items": [{"clientId": "abc", "displayText": "App"}]})
    tokens = c.list_user_oauth_tokens("user@example.edu")
    assert tokens == [{"clientId": "abc", "displayText": "App"}]
    assert t.calls[0]["userKey"] == "user@example.edu"


def test_list_user_oauth_tokens_empty_items():
    c, _ = _sec_client({})
    assert c.list_user_oauth_tokens("user@example.edu") == []


def test_list_user_oauth_tokens_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _sec_client(None, exc=err)
    with pytest.raises(GwsError):
        c.list_user_oauth_tokens("user@example.edu")


class FakeGroupsSettingsGroups:
    def __init__(self, resp, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, **kw):
        self.calls.append(kw)
        return _Req(self.resp, self.exc)


class FakeGroupsSettings:
    def __init__(self, resp, exc=None):
        self._g = FakeGroupsSettingsGroups(resp, exc)

    def groups(self):
        return self._g


def _groups_settings_client(resp, exc=None):
    svc = FakeGroupsSettings(resp, exc)
    return DomainClient(CFG, groups_settings_service=svc), svc._g


def test_get_group_settings_normalizes_string_booleans_and_passes_group_key():
    # The Groups Settings API returns "true"/"false" as JSON strings, not
    # booleans -- this must not leak into tool output.
    resp = {
        "whoCanPostMessage": "ALL_IN_DOMAIN_CAN_POST",
        "allowExternalMembers": "false",
        "isArchived": "false",
        "messageModerationLevel": "MODERATE_NONE",
        "spamModerationLevel": "MODERATE",
        "allowWebPosting": "true",
    }
    c, g = _groups_settings_client(resp)
    result = c.get_group_settings("team@example.edu")
    assert result == {
        "who_can_post": "ALL_IN_DOMAIN_CAN_POST",
        "allow_external_members": False,
        "is_archived": False,
        "message_moderation_level": "MODERATE_NONE",
        "spam_moderation_level": "MODERATE",
        "allow_web_posting": True,
    }
    assert g.calls[0]["groupUniqueId"] == "team@example.edu"


def test_get_group_settings_missing_fields_return_none_not_false():
    # A field absent from the response must stay unresolved (None), not be
    # coerced to False by the string-boolean normalizer.
    c, _ = _groups_settings_client({"whoCanPostMessage": "ANYONE_CAN_POST"})
    result = c.get_group_settings("team@example.edu")
    assert result["allow_external_members"] is None
    assert result["is_archived"] is None


def test_get_group_settings_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _ = _groups_settings_client(None, exc=err)
    with pytest.raises(GwsError):
        c.get_group_settings("nonexistent@example.edu")


def test_get_group_settings_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _groups_settings_client(None, exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.get_group_settings("team@example.edu")


class FakeDirectoryGroupsResource:
    def __init__(self, resp, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, **kw):
        self.calls.append(kw)
        return _Req(self.resp, self.exc)


class FakeDirectoryGroupService:
    def __init__(self, resp, exc=None):
        self._g = FakeDirectoryGroupsResource(resp, exc)

    def groups(self):
        return self._g


class FakeDirectoryMembersResource:
    def __init__(self, pages, exc=None):
        self.pages, self.exc, self.calls = pages, exc, []

    def list(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req(self.pages[min(len(self.calls) - 1, len(self.pages) - 1)])


class FakeDirectoryGroupMemberService:
    def __init__(self, pages, exc=None):
        self._m = FakeDirectoryMembersResource(pages, exc)

    def members(self):
        return self._m


def _group_roster_client(group_resp, group_exc, member_pages, member_exc=None):
    gsvc = FakeDirectoryGroupService(group_resp, group_exc)
    msvc = FakeDirectoryGroupMemberService(member_pages, member_exc)
    c = DomainClient(CFG, directory_group_service=gsvc, directory_group_member_service=msvc)
    return c, gsvc._g, msvc._m


def test_get_group_roster_returns_group_and_paginated_members():
    c, g, m = _group_roster_client(
        group_resp={"email": "team@example.edu", "name": "Team", "description": "d", "directMembersCount": "2"},
        group_exc=None,
        member_pages=[
            {
                "members": [{"email": "a@example.edu", "role": "MEMBER", "type": "USER", "status": "ACTIVE"}],
                "nextPageToken": "tok",
            },
            {"members": [{"email": "b@example.edu", "role": "OWNER", "type": "USER", "status": "ACTIVE"}]},
        ],
    )
    result = c.get_group_roster("team@example.edu")
    assert result["group"] == {
        "email": "team@example.edu",
        "name": "Team",
        "description": "d",
        "direct_members_count": "2",
    }
    assert [x["email"] for x in result["members"]] == ["a@example.edu", "b@example.edu"]
    assert result["members_capped"] is False
    assert g.calls[0]["groupKey"] == "team@example.edu"
    assert m.calls[0]["groupKey"] == "team@example.edu"
    assert m.calls[1]["pageToken"] == "tok"


def test_get_group_roster_caps_pages():
    c, _, _ = _group_roster_client(
        group_resp={"email": "team@example.edu"},
        group_exc=None,
        member_pages=[{"members": [{"email": "x@example.edu"}], "nextPageToken": "more"}] * 5,
    )
    result = c.get_group_roster("team@example.edu", max_pages=2)
    assert len(result["members"]) == 2
    assert result["members_capped"] is True  # stopped early with pages remaining


def test_get_group_roster_group_lookup_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _, _ = _group_roster_client(group_resp=None, group_exc=err, member_pages=[{}])
    with pytest.raises(GwsError):
        c.get_group_roster("nonexistent@example.edu")


def test_get_group_roster_member_lookup_error_maps_to_gws_error():
    # The group lookup succeeds but the member listing fails (e.g. only the
    # group.readonly scope is granted, not group.member.readonly) -- the
    # whole call must still surface as an error, not a partial/empty roster.
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _, _ = _group_roster_client(
        group_resp={"email": "team@example.edu"}, group_exc=None, member_pages=None, member_exc=err
    )
    with pytest.raises(GwsError):
        c.get_group_roster("team@example.edu")


def test_get_group_roster_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _, _ = _group_roster_client(group_resp=None, group_exc=RefreshError("unauthorized_client"), member_pages=[{}])
    with pytest.raises(GwsAuthError):
        c.get_group_roster("team@example.edu")


class FakeGmailMessagesResource:
    def __init__(self, list_resp, get_resp=None, list_exc=None, get_exc=None):
        self.list_resp, self.get_resp = list_resp, get_resp
        self.list_exc, self.get_exc = list_exc, get_exc
        self.list_calls, self.get_calls = [], []

    def list(self, **kw):
        self.list_calls.append(kw)
        return _Req(self.list_resp, self.list_exc)

    def get(self, **kw):
        self.get_calls.append(kw)
        return _Req(self.get_resp, self.get_exc)


class FakeGmailUsersResource:
    def __init__(self, messages):
        self._m = messages

    def messages(self):
        return self._m


class FakeGmailService:
    def __init__(self, messages):
        self._u = FakeGmailUsersResource(messages)

    def users(self):
        return self._u


def _gmail_client(list_resp, get_resp=None, list_exc=None, get_exc=None):
    messages = FakeGmailMessagesResource(list_resp, get_resp, list_exc, get_exc)
    svc = FakeGmailService(messages)
    c = DomainClient(CFG, gmail_service_factory=lambda user_email: svc)
    return c, messages


def test_find_message_by_id_found_returns_labels_and_headers():
    c, messages = _gmail_client(
        list_resp={"messages": [{"id": "m1", "threadId": "t1"}]},
        get_resp={
            "threadId": "t1",
            "labelIds": ["INBOX", "UNREAD"],
            "snippet": "hello",
            "internalDate": "1785794429000",
            "payload": {"headers": [{"name": "Subject", "value": "Hi"}, {"name": "Date", "value": "Wed, 1 Jan 2026"}]},
        },
    )
    found = c.find_message_by_id("user@example.edu", "<abc@agent.example>")
    assert found["label_ids"] == ["INBOX", "UNREAD"]
    assert found["headers"]["Subject"] == "Hi"
    assert found["snippet"] == "hello"
    assert found["match_count"] == 1
    # Angle brackets are stripped before being embedded in the rfc822msgid query.
    assert messages.list_calls[0]["q"] == "rfc822msgid:abc@agent.example"
    assert messages.list_calls[0]["includeSpamTrash"] is True
    assert messages.get_calls[0]["format"] == "metadata"


def test_find_message_by_id_multiple_matches_reports_match_count():
    # A mailing-list copy plus a direct CC (or a quarantine-release
    # duplicate) can land two messages under one Message-ID; the first is
    # still used for the returned fields, but match_count must say so.
    c, messages = _gmail_client(
        list_resp={"messages": [{"id": "m1"}, {"id": "m2"}]},
        get_resp={"labelIds": ["INBOX"], "snippet": "", "internalDate": "1", "payload": {}},
    )
    found = c.find_message_by_id("user@example.edu", "x@example.edu")
    assert found["match_count"] == 2
    assert found["match_count_capped"] is False  # below the page-size cap: this IS the true count
    assert messages.get_calls[0]["id"] == "m1"  # first match, not the second


def test_find_message_by_id_reports_capped_when_more_pages_exist():
    # A "nextPageToken" is Gmail's own signal that more matches exist beyond
    # this page -- the ONLY correct source for match_count_capped, since
    # this call does not paginate to find out itself.
    full_page = [{"id": f"m{i}"} for i in range(client._MESSAGE_LIST_MAX_RESULTS)]
    c, messages = _gmail_client(
        list_resp={"messages": full_page, "nextPageToken": "more"},
        get_resp={"labelIds": ["INBOX"], "snippet": "", "internalDate": "1", "payload": {}},
    )
    found = c.find_message_by_id("user@example.edu", "x@example.edu")
    assert found["match_count"] == client._MESSAGE_LIST_MAX_RESULTS
    assert found["match_count_capped"] is True
    assert messages.list_calls[0]["maxResults"] == client._MESSAGE_LIST_MAX_RESULTS


def test_find_message_by_id_not_capped_when_page_full_but_no_more_pages():
    # A mailbox with EXACTLY _MESSAGE_LIST_MAX_RESULTS matches and nothing
    # more also fills the page, but Gmail omits nextPageToken in that case --
    # match_count here IS the true count and must not be flagged as capped.
    full_page = [{"id": f"m{i}"} for i in range(client._MESSAGE_LIST_MAX_RESULTS)]
    c, _ = _gmail_client(
        list_resp={"messages": full_page},
        get_resp={"labelIds": ["INBOX"], "snippet": "", "internalDate": "1", "payload": {}},
    )
    found = c.find_message_by_id("user@example.edu", "x@example.edu")
    assert found["match_count"] == client._MESSAGE_LIST_MAX_RESULTS
    assert found["match_count_capped"] is False


def test_find_message_by_id_not_found_returns_none():
    c, _ = _gmail_client(list_resp={})
    assert c.find_message_by_id("user@example.edu", "nope@example.edu") is None


def test_find_message_by_id_list_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _gmail_client(list_resp=None, list_exc=err)
    with pytest.raises(GwsError):
        c.find_message_by_id("user@example.edu", "x@example.edu")


def test_find_message_by_id_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _gmail_client(list_resp=None, list_exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.find_message_by_id("user@example.edu", "x@example.edu")


def test_find_message_by_id_get_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "500", "reason": "boom"}), b"{}")
    c, _ = _gmail_client(list_resp={"messages": [{"id": "m1"}]}, get_resp=None, get_exc=err)
    with pytest.raises(GwsError):
        c.find_message_by_id("user@example.edu", "x@example.edu")


def test_find_message_by_id_get_auth_error_maps_to_gws_auth_error():
    # A scope/subject problem can surface on the get() call just as easily as
    # on list() (same creds/http) -- both must degrade to GwsAuthError, not
    # let the raw GoogleAuthError escape and crash the whole batch in
    # server.py's ThreadPoolExecutor loop.
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _gmail_client(
        list_resp={"messages": [{"id": "m1"}]}, get_resp=None, get_exc=RefreshError("unauthorized_client")
    )
    with pytest.raises(GwsAuthError):
        c.find_message_by_id("user@example.edu", "x@example.edu")


def test_gmail_service_factory_injection_is_not_itself_cached():
    """The factory-injection path (tests only) calls the factory every time --
    it is a deliberate bypass of ``_gmail_cache``, not a caching mechanism, so
    a test factory can hand back per-call fakes. Real per-user_email caching
    lives in the non-injected path and is covered by
    ``test_gmail_service_builds_once_and_caches_per_user_email`` below."""
    calls = []

    def factory(user_email):
        calls.append(user_email)
        return FakeGmailService(FakeGmailMessagesResource({}))

    c = DomainClient(CFG, gmail_service_factory=factory)
    c.find_message_by_id("a@example.edu", "x")
    c.find_message_by_id("a@example.edu", "y")
    assert calls == ["a@example.edu", "a@example.edu"]


def test_gmail_service_builds_once_and_caches_per_user_email(monkeypatch):
    """The real (non-factory) path must build credentials/service once per
    user_email and reuse them on a later call for the same recipient, while a
    different recipient gets its own entry."""
    build_calls = []

    def fake_from_service_account_file(filename, **kwargs):
        return ("creds", filename, kwargs.get("subject"))

    def fake_build(service_name, version, credentials=None, cache_discovery=None):
        build_calls.append((service_name, version, credentials))
        return object()

    monkeypatch.setattr(client.service_account.Credentials, "from_service_account_file", fake_from_service_account_file)
    monkeypatch.setattr(client, "build", fake_build)

    c = DomainClient(CFG)
    svc1, creds1 = c._gmail_service("a@example.edu")
    svc2, creds2 = c._gmail_service("a@example.edu")
    assert svc1 is svc2  # second call for the same user reused the cache entry
    assert creds1 == creds2
    assert len(build_calls) == 1

    svc3, _ = c._gmail_service("b@example.edu")
    assert svc3 is not svc1  # a different recipient gets its own service/creds
    assert len(build_calls) == 2


def test_gmail_service_cache_evicts_oldest_once_over_cap(monkeypatch):
    # _gmail_cache accumulates one entry per distinct recipient ever traced
    # across this process's lifetime (not per call), so it must not grow
    # without bound -- verify the FIFO eviction with a cap small enough to
    # exercise cheaply.
    monkeypatch.setattr(client, "_GMAIL_CACHE_MAX", 2)
    monkeypatch.setattr(
        client.service_account.Credentials, "from_service_account_file", lambda filename, **kw: object()
    )
    monkeypatch.setattr(client, "build", lambda *a, **kw: object())

    c = DomainClient(CFG)
    c._gmail_service("a@example.edu")
    c._gmail_service("b@example.edu")
    assert list(c._gmail_cache) == ["a@example.edu", "b@example.edu"]

    c._gmail_service("c@example.edu")  # over cap: evicts "a" (oldest)
    assert list(c._gmail_cache) == ["b@example.edu", "c@example.edu"]


def test_http_error_maps_to_gws_error():
    import datetime

    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _client([], exc=err)
    with pytest.raises(GwsError):
        c.fetch_activities("login", start=datetime.datetime.now(datetime.timezone.utc))


def test_check_reports_error_as_structured_result():
    err = HttpError(httplib2.Response({"status": "401", "reason": "unauthorized"}), b"{}")
    c, _ = _client([], exc=err)
    out = c.check()
    assert out["auth"] == "error" and "401" in out["detail"]


def test_google_auth_error_maps_to_gws_auth_error():
    import datetime

    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _client([], exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.fetch_activities("login", start=datetime.datetime.now(datetime.timezone.utc))


def test_transport_error_maps_to_gws_error_without_traceback():
    import datetime

    c, _ = _client([], exc=httplib2.ServerNotFoundError("no dns"))
    with pytest.raises(GwsError):
        c.fetch_activities("login", start=datetime.datetime.now(datetime.timezone.utc))


def test_key_load_failure_does_not_leak_path(tmp_path):
    from gwsadm_mcp.client import GwsAuthError

    secret_path = str(tmp_path / "very-secret-key.json")
    cfg = DomainConfig("example.edu", secret_path, "a@example.edu", "C0abc")
    c = DomainClient(cfg)  # no injected service -> loads the key file
    with pytest.raises(GwsAuthError) as ei:
        c._reports_service()
    assert secret_path not in str(ei.value)
    assert "very-secret-key" not in str(ei.value)


def test_check_never_raises_even_on_unexpected_error():
    class Boom:
        def activities(self):
            raise RuntimeError("unexpected")

    c = DomainClient(CFG, reports_service=Boom())
    out = c.check()
    assert out["auth"] == "error" and "RuntimeError" in out["detail"]


def test_event_parameters_value_precedence():
    from gwsadm_mcp.client import event_parameters

    ev = {"parameters": [{"name": "x", "value": "s", "boolValue": True}]}
    assert event_parameters(ev) == {"x": "s"}  # value wins over boolValue


def test_event_parameters_flattens_value_kinds():
    ev = {
        "parameters": [
            {"name": "doc_title", "value": "Plan"},
            {"name": "billable", "boolValue": True},
            {"name": "old_visibility", "multiValue": ["private"]},
        ]
    }
    p = event_parameters(ev)
    assert p == {"doc_title": "Plan", "billable": True, "old_visibility": ["private"]}


# --- thread-safety + rate-limit retry (parallel-fetch foundation) ---


def test_new_http_is_none_without_real_creds():
    c, _ = _client([])  # injected mock service -> no credentials built
    assert c._new_http() is None  # execute() falls back to the request transport


def test_new_http_is_authorized_when_creds_present():
    import google_auth_httplib2

    c, _ = _client([])
    c._creds = object()  # sentinel: AuthorizedHttp only stores it, never calls it here
    assert isinstance(c._new_http(), google_auth_httplib2.AuthorizedHttp)


def test_is_retryable_classification():
    from gwsadm_mcp.client import _is_retryable

    def err(status, body=b"{}"):
        return HttpError(httplib2.Response({"status": str(status)}), body)

    assert _is_retryable(err(429)) is True
    assert _is_retryable(err(500)) is True
    assert _is_retryable(err(503)) is True
    assert _is_retryable(err(404)) is False
    assert _is_retryable(err(403, b'{"error":"forbidden"}')) is False  # permission -> fail fast
    assert _is_retryable(err(403, b'{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}')) is True


def test_rate_limit_is_retried_with_backoff(monkeypatch):
    import datetime

    slept: list = []
    monkeypatch.setattr("gwsadm_mcp.client.time.sleep", lambda s: slept.append(s))
    err429 = HttpError(httplib2.Response({"status": "429"}), b"{}")

    class _Seq:
        def __init__(self, results):
            self.results, self.i = results, 0

        def execute(self, http=None):
            r = self.results[self.i]
            self.i += 1
            if isinstance(r, Exception):
                raise r
            return r

    class _Acts:
        def __init__(self, seq):
            self._seq = seq

        def list(self, **kw):
            return self._seq

    class _Rep:
        def __init__(self, seq):
            self._acts = _Acts(seq)

        def activities(self):
            return self._acts

    seq = _Seq([err429, {"items": [{"id": {"time": "t"}}]}])  # 429 once, then a page
    c = DomainClient(CFG, reports_service=_Rep(seq))
    items, capped = c.fetch_activities("login", start=datetime.datetime.now(datetime.timezone.utc))
    assert len(items) == 1 and capped is False
    assert len(slept) == 1 and 1.0 <= slept[0] <= 2.0  # one jittered backoff (base 1.0 + [0,1))


def test_permission_403_is_not_retried(monkeypatch):
    import datetime

    slept: list = []
    monkeypatch.setattr("gwsadm_mcp.client.time.sleep", lambda s: slept.append(s))
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _client([], exc=err)
    with pytest.raises(GwsError):
        c.fetch_activities("login", start=datetime.datetime.now(datetime.timezone.utc))
    assert slept == []  # no backoff for a permanent permission error


def test_fetch_activities_passes_filters_only_when_set():
    import datetime

    c, a = _client([{"items": []}, {"items": []}])
    start = datetime.datetime(2026, 7, 1, tzinfo=datetime.timezone.utc)
    c.fetch_activities("drive", start=start, filters="doc_id==abc123defg")
    assert a.calls[0]["filters"] == "doc_id==abc123defg"
    c.fetch_activities("drive", start=start)
    assert "filters" not in a.calls[1]
