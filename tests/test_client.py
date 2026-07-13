"""Tests for DomainClient (paging, capped flag, error mapping, param flattening)."""

import httplib2
import pytest
from googleapiclient.errors import HttpError

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
