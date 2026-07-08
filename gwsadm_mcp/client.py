"""Read-only Google Workspace Admin API client (service account + DWD).

One ``DomainClient`` per audited domain. Auth is a service account with
domain-wide delegation impersonating an audit-capable admin (``subject``) —
fully non-interactive, so the server can run unattended behind a gateway.

Read-only by design: only ``activities().list`` (Admin SDK Reports API) is
issued; no mutating call exists in this package.
"""

import datetime

import httplib2
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from gwsadm_mcp.config import DomainConfig

SCOPE_REPORTS = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

# Reports API hard limit is 1000 per page.
PAGE_SIZE = 1000


class GwsError(Exception):
    """Base error for Workspace Admin API failures."""


class GwsAuthError(GwsError):
    """Auth failure (bad key file, missing DWD scope, wrong subject)."""


def _rfc3339(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class DomainClient:
    """Audit-activities client for one Workspace domain."""

    def __init__(self, cfg: DomainConfig, *, reports_service=None):
        self.cfg = cfg
        self._reports = reports_service  # injectable for tests

    @property
    def domain(self) -> str:
        return self.cfg.domain

    def _reports_service(self):
        if self._reports is None:
            try:
                creds = service_account.Credentials.from_service_account_file(
                    self.cfg.service_account_file, scopes=[SCOPE_REPORTS], subject=self.cfg.subject
                )
            except (OSError, ValueError) as e:
                # Exception text deliberately omitted: it may embed the key path,
                # which must not leak into tool output visible to MCP clients.
                raise GwsAuthError(f"[{self.domain}] cannot load service account key ({type(e).__name__})") from e
            self._reports = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
        return self._reports

    def fetch_activities(
        self,
        application_name: str,
        *,
        start: datetime.datetime,
        end: datetime.datetime | None = None,
        event_name: str | None = None,
        max_pages: int = 5,
    ) -> tuple[list[dict], bool]:
        """Fetch audit activities (newest first). Returns ``(items, capped)``.

        ``capped=True`` means more pages existed beyond ``max_pages`` — callers
        must surface this so a partial window is never mistaken for full coverage.
        """
        params = {
            "userKey": "all",
            "applicationName": application_name,
            "customerId": self.cfg.customer_id,
            "startTime": _rfc3339(start),
            "maxResults": PAGE_SIZE,
        }
        if end is not None:
            params["endTime"] = _rfc3339(end)
        if event_name:
            params["eventName"] = event_name
        items: list[dict] = []
        token = None
        pages = 0
        try:
            svc = self._reports_service()
            while True:
                resp = svc.activities().list(pageToken=token, **params).execute()
                items.extend(resp.get("items", []))
                token = resp.get("nextPageToken")
                pages += 1
                if not token or pages >= max_pages:
                    break
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] reports API error ({application_name}): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: DWD scope not granted for this client, or wrong subject.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error ({application_name}): {type(e).__name__}") from e
        return items, bool(token)

    def check(self) -> dict:
        """Cheap end-to-end probe: one 1-item login query (auth + API + DWD)."""
        start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        try:
            svc = self._reports_service()
            svc.activities().list(
                userKey="all",
                applicationName="login",
                customerId=self.cfg.customer_id,
                startTime=_rfc3339(start),
                maxResults=1,
            ).execute()
            return {"domain": self.domain, "auth": "ok"}
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            return {"domain": self.domain, "auth": "error", "detail": f"HTTP {status}"}
        except Exception as e:  # a health probe must always return the same keys
            return {"domain": self.domain, "auth": "error", "detail": f"{type(e).__name__}: {str(e)[:200]}"}


def event_parameters(event: dict) -> dict:
    """Flatten an activity event's ``parameters`` list into a plain dict."""
    out: dict = {}
    for p in event.get("parameters", []) or []:
        name = p.get("name")
        if not name:
            continue
        for key in ("value", "boolValue", "intValue"):
            if key in p:
                out[name] = p[key]
                break
        else:
            if "multiValue" in p:
                out[name] = p["multiValue"]
    return out
