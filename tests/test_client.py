"""Tests for DomainClient (paging, capped flag, error mapping, param flattening)."""

import httplib2
import pytest
from googleapiclient.errors import HttpError

import gwsadm_mcp.client as client
from gwsadm_mcp.client import DomainClient, GwsError, event_parameters
from gwsadm_mcp.config import DomainConfig

CFG = DomainConfig("example.edu", "/tmp/sa.json", "audit-admin@example.edu", "C0abc", "postmaster@example.edu")


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


class FakeCustomerUsageReports:
    def __init__(self, pages, exc=None):
        self.pages, self.exc, self.calls = pages, exc, []

    def get(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req(self.pages[min(len(self.calls) - 1, len(self.pages) - 1)])


class FakeReportsUsage:
    def __init__(self, pages, exc=None):
        self._u = FakeCustomerUsageReports(pages, exc)

    def customerUsageReports(self):
        return self._u


def _usage_client(pages, exc=None):
    svc = FakeReportsUsage(pages, exc)
    return DomainClient(CFG, reports_usage_service=svc), svc._u


def test_fetch_customer_usage_paginates_and_passes_params():
    c, u = _usage_client(
        [
            {
                "usageReports": [
                    {"date": "2026-08-30", "parameters": [{"name": "gmail:num_emails_sent", "intValue": "10"}]}
                ],
                "nextPageToken": "tok",
            },
            {"usageReports": [{"date": "2026-08-30", "parameters": []}]},
        ]
    )
    reports, capped = c.fetch_customer_usage(date="2026-08-30", parameters="gmail:num_emails_sent")
    assert len(reports) == 2 and capped is False
    assert u.calls[0]["date"] == "2026-08-30"
    assert u.calls[0]["customerId"] == "C0abc"
    assert u.calls[0]["parameters"] == "gmail:num_emails_sent"
    assert u.calls[1]["pageToken"] == "tok"


def test_fetch_customer_usage_omits_parameters_filter_when_not_given():
    c, u = _usage_client([{"usageReports": []}])
    c.fetch_customer_usage(date="2026-08-30")
    assert "parameters" not in u.calls[0]


def test_fetch_customer_usage_caps_pages():
    c, _ = _usage_client([{"usageReports": [{}], "nextPageToken": "more"}] * 5)
    reports, capped = c.fetch_customer_usage(date="2026-08-30", max_pages=2)
    assert len(reports) == 2 and capped is True


def test_fetch_customer_usage_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _usage_client([], exc=err)
    with pytest.raises(GwsError):
        c.fetch_customer_usage(date="2026-08-30")


def test_fetch_customer_usage_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _usage_client([], exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.fetch_customer_usage(date="2026-08-30")


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


class FakeDirectoryUsersResource:
    def __init__(self, resp, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def get(self, **kw):
        self.calls.append(kw)
        return _Req(self.resp, self.exc)


class FakeDirectoryUserService:
    def __init__(self, resp, exc=None):
        self._u = FakeDirectoryUsersResource(resp, exc)

    def users(self):
        return self._u


def _user_client(resp, exc=None):
    svc = FakeDirectoryUserService(resp, exc)
    return DomainClient(CFG, directory_service=svc), svc._u


def test_get_user_returns_raw_record_and_passes_user_key():
    # Guards the wiring get_user is entirely made of: the full email reaches
    # the API as userKey (not just the local part), the response comes back
    # unprojected for server.py to shape, and projection stays pinned to
    # "basic" so a tenant's custom user schemas are never pulled in.
    c, u = _user_client({"primaryEmail": "user@example.edu", "suspended": True})
    assert c.get_user("user@example.edu") == {"primaryEmail": "user@example.edu", "suspended": True}
    assert u.calls[0]["userKey"] == "user@example.edu"
    assert u.calls[0]["projection"] == "basic"


def test_get_user_not_found_returns_none():
    # The headline behaviour of issue #68: a 404 means the address names no
    # account -- a normal, expected answer, not a failure. Raising here would
    # make "this account does not exist" indistinguishable from "the lookup
    # broke", which is the whole diagnostic value of the tool.
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _ = _user_client(None, exc=err)
    assert c.get_user("nonexistent@example.edu") is None


def test_get_user_non_404_http_error_maps_to_gws_error():
    # A permission 403 must NOT be swallowed as "not found" -- that would
    # report a missing DWD scope as a confirmed-nonexistent account and send
    # an operator hunting for a typo that isn't there.
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _user_client(None, exc=err)
    with pytest.raises(GwsError):
        c.get_user("user@example.edu")


def test_get_user_auth_error_maps_to_gws_auth_error():
    # Same split the other per-user lookups keep: a credential/scope failure
    # is GwsAuthError (the whole domain is unusable), never a bare GwsError
    # and never a None that would read as not-found.
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _user_client(None, exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.get_user("user@example.edu")


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


def test_get_group_settings_not_found_returns_none():
    # A plain 404 means the address is not a group -- a normal, expected
    # answer distinguished from a raised GwsError (any other HTTP status).
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _ = _groups_settings_client(None, exc=err)
    assert c.get_group_settings("nonexistent@example.edu") is None


def test_get_group_settings_non_404_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _groups_settings_client(None, exc=err)
    with pytest.raises(GwsError):
        c.get_group_settings("team@example.edu")


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


def _group_client(resp, exc=None):
    svc = FakeDirectoryGroupService(resp, exc)
    return DomainClient(CFG, directory_group_service=svc), svc._g


def _group_member_client(pages, exc=None):
    svc = FakeDirectoryGroupMemberService(pages, exc)
    return DomainClient(CFG, directory_group_member_service=svc), svc._m


def test_get_group_returns_projected_metadata_and_passes_group_key():
    c, g = _group_client({"email": "team@example.edu", "name": "Team", "description": "d", "directMembersCount": "2"})
    result = c.get_group("team@example.edu")
    assert result == {"email": "team@example.edu", "name": "Team", "description": "d", "direct_members_count": "2"}
    assert g.calls[0]["groupKey"] == "team@example.edu"


def test_get_group_not_found_returns_none():
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _ = _group_client(None, exc=err)
    assert c.get_group("nonexistent@example.edu") is None


def test_get_group_non_404_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "500", "reason": "boom"}), b"{}")
    c, _ = _group_client(None, exc=err)
    with pytest.raises(GwsError):
        c.get_group("team@example.edu")


def test_get_group_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _group_client(None, exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.get_group("team@example.edu")


def test_list_group_members_paginates_and_passes_group_key():
    c, m = _group_member_client(
        [
            {
                "members": [{"email": "a@example.edu", "role": "MEMBER", "type": "USER", "status": "ACTIVE"}],
                "nextPageToken": "tok",
            },
            {"members": [{"email": "b@example.edu", "role": "OWNER", "type": "USER", "status": "ACTIVE"}]},
        ]
    )
    members, capped = c.list_group_members("team@example.edu")
    assert [x["email"] for x in members] == ["a@example.edu", "b@example.edu"]
    assert capped is False
    assert m.calls[0]["groupKey"] == "team@example.edu"
    assert m.calls[1]["pageToken"] == "tok"


def test_list_group_members_caps_pages():
    c, _ = _group_member_client([{"members": [{"email": "x@example.edu"}], "nextPageToken": "more"}] * 5)
    members, capped = c.list_group_members("team@example.edu", max_pages=2)
    assert len(members) == 2
    assert capped is True  # stopped early with pages remaining


def test_list_group_members_not_found_on_first_page_returns_none():
    # A 404 on the very first page means the group itself doesn't exist.
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")
    c, _ = _group_member_client(None, exc=err)
    assert c.list_group_members("nonexistent@example.edu") is None


def test_list_group_members_404_on_later_page_still_raises():
    # A group that existed when listing started but was deleted mid-pagination
    # is not "not found" -- it must stay a real error, not silently report a
    # partial roster (or None) as though the group never existed.
    err = HttpError(httplib2.Response({"status": "404", "reason": "not found"}), b"{}")

    class _FlakyMembersResource:
        def __init__(self):
            self.calls = 0

        def list(self, **kw):
            self.calls += 1
            if self.calls == 1:
                return _Req({"members": [{"email": "a@example.edu"}], "nextPageToken": "tok"})
            return _Req(None, err)

    class _FlakyService:
        def __init__(self, resource):
            self._m = resource

        def members(self):
            return self._m

    resource = _FlakyMembersResource()
    c = DomainClient(CFG, directory_group_member_service=_FlakyService(resource))
    with pytest.raises(GwsError):
        c.list_group_members("team@example.edu")


def test_list_group_members_non_404_http_error_maps_to_gws_error():
    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _group_member_client(None, exc=err)
    with pytest.raises(GwsError):
        c.list_group_members("team@example.edu")


def test_list_group_members_auth_error_maps_to_gws_auth_error():
    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _group_member_client(None, exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.list_group_members("team@example.edu")


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


# -- fetch_dmarc_rua_records / DMARC XML parsing -----------------------------


def _dmarc_xml(policy_domain, records):
    """Build a minimal DMARC aggregate-report XML document from simple dicts."""
    parts = [f"<feedback><policy_published><domain>{policy_domain}</domain></policy_published>"]
    for r in records:
        parts.append(
            f"<record><row><source_ip>{r['source_ip']}</source_ip><count>{r['count']}</count>"
            f"<policy_evaluated><disposition>{r['disposition']}</disposition>"
            f"<dkim>{r['dkim']}</dkim><spf>{r['spf']}</spf></policy_evaluated></row>"
            f"<identifiers><header_from>{r['header_from']}</header_from></identifiers></record>"
        )
    parts.append("</feedback>")
    return "".join(parts).encode()


def _gzip_b64(raw_bytes):
    import base64
    import gzip

    # urlsafe_b64encode's trailing '=' padding is stripped, matching real
    # Gmail attachment "data" fields (see fetch_dmarc_rua_records, which
    # re-pads before decoding) -- this exercises that re-padding path too.
    return base64.urlsafe_b64encode(gzip.compress(raw_bytes)).decode().rstrip("=")


def test_find_attachment_id_top_level():
    assert client._find_attachment_id({"body": {"attachmentId": "a1"}}) == "a1"


def test_find_attachment_id_nested_in_parts():
    payload = {"body": {}, "parts": [{"body": {}}, {"body": {"attachmentId": "a2"}}]}
    assert client._find_attachment_id(payload) == "a2"


def test_find_attachment_id_none_when_absent():
    assert client._find_attachment_id({"body": {}, "parts": [{"body": {}}]}) is None


def test_decode_report_payload_gzip_roundtrip():
    import gzip

    xml = b"<feedback>gzip</feedback>"
    assert client._decode_report_payload(gzip.compress(xml)) == xml


def test_decode_report_payload_truncated_gzip_does_not_raise():
    # Regression test for a /code-review high finding on PR #79: a truncated
    # gzip stream (e.g. cut off mid-transfer) raises EOFError from
    # gzip.decompress(), not OSError -- the original except OSError clause
    # let this escape uncaught, which would abort fetch_dmarc_rua_records'
    # whole domain fetch instead of counting one message error like every
    # other malformed-attachment case.
    import gzip

    xml = b"<feedback>gzip</feedback>"
    truncated = gzip.compress(xml)[:-4]  # chop the end-of-stream trailer
    assert client._decode_report_payload(truncated) == truncated


def test_decode_report_payload_corrupted_gzip_body_does_not_raise():
    # Same finding, the zlib.error trigger: a gzip-magic-valid header with a
    # corrupted deflate body raises zlib.error from the underlying zlib
    # layer, also not an OSError subclass.
    import gzip

    xml = b"<feedback>gzip corrupted body test payload</feedback>"
    compressed = bytearray(gzip.compress(xml))
    mid = len(compressed) // 2
    compressed[mid] ^= 0xFF  # flip a byte inside the deflate-compressed body
    corrupted = bytes(compressed)
    assert client._decode_report_payload(corrupted) == corrupted


def test_decode_report_payload_zip_roundtrip():
    import io
    import zipfile

    xml = b"<feedback>zip</feedback>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", xml)
    assert client._decode_report_payload(buf.getvalue()) == xml


def test_decode_report_payload_empty_zip_does_not_raise():
    # Regression test for a Copilot review finding on PR #79: a valid ZIP
    # with zero entries made zf.namelist()[0] raise IndexError, which would
    # escape the per-message exception handling in fetch_dmarc_rua_records
    # and abort the whole domain's fetch instead of counting one message
    # error. Treated the same as "not a zip at all" -- returned as-is.
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass  # zero entries
    assert client._decode_report_payload(buf.getvalue()) == buf.getvalue()


def test_decode_report_payload_plain_xml_passthrough():
    xml = b"<feedback>plain</feedback>"
    assert client._decode_report_payload(xml) == xml


def test_parse_dmarc_records_extracts_all_fields():
    xml = _dmarc_xml(
        "example.edu",
        [
            {
                "source_ip": "1.2.3.4",
                "count": 5,
                "dkim": "pass",
                "spf": "fail",
                "disposition": "none",
                "header_from": "example.edu",
            }
        ],
    )
    assert client._parse_dmarc_records(xml) == [
        {
            "policy_domain": "example.edu",
            "source_ip": "1.2.3.4",
            "count": 5,
            "dkim": "pass",
            "spf": "fail",
            "disposition": "none",
            "header_from": "example.edu",
        }
    ]


def test_parse_dmarc_records_skips_record_with_missing_count():
    xml = (
        b"<feedback><policy_published><domain>example.edu</domain></policy_published>"
        b"<record><row><source_ip>1.2.3.4</source_ip></row></record></feedback>"
    )
    assert client._parse_dmarc_records(xml) == []


class FakeGmailAttachmentsResource:
    def __init__(self, by_id, exc=None):
        self._by_id, self.exc = by_id, exc
        self.calls = []

    def get(self, **kw):
        self.calls.append(kw)
        if self.exc:
            return _Req(None, self.exc)
        return _Req({"data": self._by_id.get(kw["id"], "")})


class FakeGmailMessagesResourceDmarc:
    """Like FakeGmailMessagesResource, but also exposes attachments()."""

    def __init__(self, list_pages, get_by_id, attachments, list_exc=None, get_exc=None):
        self.list_pages, self.get_by_id = list_pages, get_by_id
        self._attachments = attachments
        self.list_exc, self.get_exc = list_exc, get_exc
        self.list_calls, self.get_calls = [], []

    def list(self, **kw):
        self.list_calls.append(kw)
        if self.list_exc:
            return _Req(None, self.list_exc)
        return _Req(self.list_pages[min(len(self.list_calls) - 1, len(self.list_pages) - 1)])

    def get(self, **kw):
        self.get_calls.append(kw)
        if self.get_exc:
            return _Req(None, self.get_exc)
        return _Req(self.get_by_id[kw["id"]])

    def attachments(self):
        return self._attachments


def _dmarc_client(
    list_pages, get_by_id=None, attachments_by_id=None, list_exc=None, get_exc=None, attachments_exc=None
):
    messages = FakeGmailMessagesResourceDmarc(
        list_pages,
        get_by_id or {},
        FakeGmailAttachmentsResource(attachments_by_id or {}, attachments_exc),
        list_exc,
        get_exc,
    )
    svc = FakeGmailUsersResource(messages)

    class _Svc:
        def users(self):
            return svc

    c = DomainClient(CFG, gmail_service_factory=lambda user_email: _Svc())
    return c, messages


def test_fetch_dmarc_rua_records_happy_path_parses_and_defaults_mailbox():
    import datetime

    xml = _dmarc_xml(
        "example.edu",
        [
            {
                "source_ip": "1.2.3.4",
                "count": 3,
                "dkim": "pass",
                "spf": "pass",
                "disposition": "none",
                "header_from": "example.edu",
            }
        ],
    )
    c, messages = _dmarc_client(
        list_pages=[{"messages": [{"id": "m1"}]}],
        get_by_id={"m1": {"payload": {"body": {"attachmentId": "att1"}}}},
        attachments_by_id={"att1": _gzip_b64(xml)},
    )
    records, capped, message_errors, mailbox = c.fetch_dmarc_rua_records(
        start=datetime.datetime.now(datetime.timezone.utc)
    )
    assert records == [
        {
            "policy_domain": "example.edu",
            "source_ip": "1.2.3.4",
            "count": 3,
            "dkim": "pass",
            "spf": "pass",
            "disposition": "none",
            "header_from": "example.edu",
        }
    ]
    assert capped is False
    assert message_errors == 0
    assert mailbox == "postmaster@example.edu"  # CFG.dmarc_rua_mailbox default
    assert "to:postmaster@example.edu" in messages.list_calls[0]["q"]


def test_fetch_dmarc_rua_records_honors_explicit_mailbox_override():
    import datetime

    c, messages = _dmarc_client(list_pages=[{"messages": []}])
    _, _, _, mailbox = c.fetch_dmarc_rua_records(
        start=datetime.datetime.now(datetime.timezone.utc), mailbox="dmarc-reports@example.edu"
    )
    assert mailbox == "dmarc-reports@example.edu"
    assert "to:dmarc-reports@example.edu" in messages.list_calls[0]["q"]


def test_fetch_dmarc_rua_records_message_with_no_attachment_counts_as_error():
    import datetime

    c, _ = _dmarc_client(
        list_pages=[{"messages": [{"id": "m1"}]}],
        get_by_id={"m1": {"payload": {"body": {}}}},  # no attachmentId anywhere
    )
    records, _, message_errors, _ = c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))
    assert records == []
    assert message_errors == 1


def test_fetch_dmarc_rua_records_malformed_attachment_counts_as_error_not_raise():
    import datetime

    c, _ = _dmarc_client(
        list_pages=[{"messages": [{"id": "m1"}]}],
        get_by_id={"m1": {"payload": {"body": {"attachmentId": "att1"}}}},
        attachments_by_id={"att1": "not-valid-base64-or-xml!!!"},
    )
    records, _, message_errors, _ = c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))
    assert records == []
    assert message_errors == 1


def test_fetch_dmarc_rua_records_capped_when_more_pages_exist_than_max_pages():
    import datetime

    c, _ = _dmarc_client(list_pages=[{"messages": [], "nextPageToken": "tok2"}])
    _, capped, _, _ = c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc), max_pages=1)
    assert capped is True


def test_fetch_dmarc_rua_records_not_capped_when_no_more_pages():
    import datetime

    c, _ = _dmarc_client(list_pages=[{"messages": []}])
    _, capped, _, _ = c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc), max_pages=5)
    assert capped is False


def test_fetch_dmarc_rua_records_list_http_error_maps_to_gws_error():
    import datetime

    err = HttpError(httplib2.Response({"status": "403", "reason": "forbidden"}), b"{}")
    c, _ = _dmarc_client(list_pages=[{}], list_exc=err)
    with pytest.raises(GwsError):
        c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))


def test_fetch_dmarc_rua_records_list_auth_error_maps_to_gws_auth_error():
    import datetime

    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _dmarc_client(list_pages=[{}], list_exc=RefreshError("unauthorized_client"))
    with pytest.raises(GwsAuthError):
        c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))


def test_fetch_dmarc_rua_records_per_message_auth_error_fails_the_whole_fetch():
    """A GoogleAuthError from one message's get() means the scope/mailbox is
    broken for every message identically -- it must propagate as GwsAuthError,
    not get silently counted as one of many tolerated per-message errors."""
    import datetime

    from google.auth.exceptions import RefreshError

    from gwsadm_mcp.client import GwsAuthError

    c, _ = _dmarc_client(
        list_pages=[{"messages": [{"id": "m1"}]}],
        get_exc=RefreshError("unauthorized_client"),
    )
    with pytest.raises(GwsAuthError):
        c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))


def test_fetch_dmarc_rua_records_one_bad_message_does_not_lose_other_records():
    import datetime

    good_xml = _dmarc_xml(
        "example.edu",
        [
            {
                "source_ip": "9.9.9.9",
                "count": 1,
                "dkim": "pass",
                "spf": "pass",
                "disposition": "none",
                "header_from": "example.edu",
            }
        ],
    )
    c, _ = _dmarc_client(
        list_pages=[{"messages": [{"id": "good"}, {"id": "bad"}]}],
        get_by_id={
            "good": {"payload": {"body": {"attachmentId": "att-good"}}},
            "bad": {"payload": {"body": {}}},  # no attachment
        },
        attachments_by_id={"att-good": _gzip_b64(good_xml)},
    )
    records, _, message_errors, _ = c.fetch_dmarc_rua_records(start=datetime.datetime.now(datetime.timezone.utc))
    assert len(records) == 1
    assert records[0]["source_ip"] == "9.9.9.9"
    assert message_errors == 1


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
    cfg = DomainConfig("example.edu", secret_path, "a@example.edu", "C0abc", "postmaster@example.edu")
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
