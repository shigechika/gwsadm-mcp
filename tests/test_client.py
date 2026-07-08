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

    def execute(self):
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
