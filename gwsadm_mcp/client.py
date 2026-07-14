"""Read-only Google Workspace Admin API client (service account + DWD).

One ``DomainClient`` per audited domain. Auth is a service account with
domain-wide delegation impersonating an audit-capable admin (``subject``) —
fully non-interactive, so the server can run unattended behind a gateway.

Read-only by design: only ``activities().list`` (Admin SDK Reports API),
``users().list`` (Directory API, for suspended-account snapshots), and
``tokens().list`` (Directory API, for per-user OAuth app grants) are issued;
no mutating call exists in this package.
"""

import datetime
import random
import threading
import time

import google_auth_httplib2
import httplib2
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from gwsadm_mcp.config import DomainConfig

SCOPE_REPORTS = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
SCOPE_DIRECTORY = "https://www.googleapis.com/auth/admin.directory.user.readonly"
# Tokens().list (third-party OAuth app grants) lives under the Directory API but
# is NOT covered by admin.directory.user.readonly -- it needs this separate,
# more sensitive scope (a user's security/2SV/token resource), hence its own
# credentials and service builder below rather than reusing _directory_service.
SCOPE_DIRECTORY_SECURITY = "https://www.googleapis.com/auth/admin.directory.user.security"

# Reports API hard limit is 1000 per page.
PAGE_SIZE = 1000
# Directory API hard limit is 500 per page.
DIRECTORY_PAGE_SIZE = 500

# Per-request HTTP timeout (seconds).
_HTTP_TIMEOUT = 30
# Backoff-retry budget for rate-limit / transient server errors.
_MAX_RETRIES = 5
_MAX_BACKOFF = 8.0


def _is_retryable(e: HttpError) -> bool:
    """True for a rate-limit / transient server error worth a backoff-retry.

    A 403 is retried ONLY when its body names a rate/quota reason — a plain
    permission 403 (e.g. DWD scope not granted) is permanent and must fail fast.
    """
    status = int(getattr(getattr(e, "resp", None), "status", 0) or 0)
    if status in (429, 500, 503):
        return True
    if status == 403:
        blob = getattr(e, "content", b"") or b""
        if isinstance(blob, bytes):
            blob = blob.decode("utf-8", "replace")
        blob = blob.lower()
        return any(r in blob for r in ("ratelimitexceeded", "userratelimitexceeded", "quotaexceeded"))
    return False


class GwsError(Exception):
    """Base error for Workspace Admin API failures."""


class GwsAuthError(GwsError):
    """Auth failure (bad key file, missing DWD scope, wrong subject)."""


def _rfc3339(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class DomainClient:
    """Audit-activities client for one Workspace domain."""

    def __init__(
        self,
        cfg: DomainConfig,
        *,
        reports_service=None,
        directory_service=None,
        directory_security_service=None,
    ):
        self.cfg = cfg
        self._reports = reports_service  # injectable for tests
        self._directory = directory_service  # injectable for tests
        self._directory_security = directory_security_service  # injectable for tests
        self._creds = None
        self._directory_creds = None
        self._directory_security_creds = None
        # Guards the lazy build so concurrent fetch_activities() calls (the
        # parallel daily_brief) build the service/credentials at most once.
        self._build_lock = threading.Lock()

    @property
    def domain(self) -> str:
        return self.cfg.domain

    def _reports_service(self):
        if self._reports is None:
            with self._build_lock:
                if self._reports is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file, scopes=[SCOPE_REPORTS], subject=self.cfg.subject
                        )
                    except (OSError, ValueError) as e:
                        # Exception text deliberately omitted: it may embed the key path,
                        # which must not leak into tool output visible to MCP clients.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._creds = creds
                    self._reports = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
        return self._reports

    def _directory_service(self):
        if self._directory is None:
            with self._build_lock:
                if self._directory is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file, scopes=[SCOPE_DIRECTORY], subject=self.cfg.subject
                        )
                    except (OSError, ValueError) as e:
                        # See _reports_service: key path must not leak into tool output.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._directory_creds = creds
                    self._directory = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        return self._directory

    def _directory_security_service(self):
        if self._directory_security is None:
            with self._build_lock:
                if self._directory_security is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file, scopes=[SCOPE_DIRECTORY_SECURITY], subject=self.cfg.subject
                        )
                    except (OSError, ValueError) as e:
                        # See _reports_service: key path must not leak into tool output.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._directory_security_creds = creds
                    self._directory_security = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        return self._directory_security

    def _new_http(self, creds=None):
        """A fresh AuthorizedHttp per call so concurrent execute()s are thread-safe.

        googleapiclient's service object may be shared across threads, but its
        underlying httplib2.Http is not — the supported pattern is one Http per
        thread, passed to execute(http=...). ``creds`` selects the credential
        set (reports vs directory); defaults to the reports creds. Returns None
        when no real credentials exist (an injected mock service in tests),
        which makes execute() fall back to the request's own transport.
        """
        creds = creds or self._creds
        if creds is None:
            return None
        return google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http(timeout=_HTTP_TIMEOUT))

    def _execute(self, make_request, http):
        """Execute a freshly-built request with backoff on rate-limit/transient errors."""
        for attempt in range(_MAX_RETRIES):
            try:
                return make_request().execute(http=http)
            except HttpError as e:
                if attempt + 1 < _MAX_RETRIES and _is_retryable(e):
                    # Full jitter (base + random[0, base]): when many parallel
                    # fetches are throttled at the same instant, deterministic
                    # backoff would retry them in lockstep and re-collide.
                    base = min(2.0**attempt, _MAX_BACKOFF)
                    time.sleep(base + random.uniform(0, base))
                    continue
                raise
        # Unreachable: the final attempt either returns or raises.
        raise AssertionError("unreachable")  # pragma: no cover

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
            http = self._new_http()
            while True:
                resp = self._execute(lambda tok=token: svc.activities().list(pageToken=tok, **params), http)
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

    def list_suspended_users(self, *, max_pages: int = 20) -> tuple[list[dict], bool]:
        """List currently suspended users in this domain (Directory API).

        Returns ``(users, capped)``; ``capped=True`` means more pages existed
        beyond ``max_pages`` — callers must surface this so a partial snapshot is
        never mistaken for the full set. Read-only: only ``users().list`` is
        issued. Requires the ``admin.directory.user.readonly`` DWD scope; a
        missing grant surfaces as a permission error, never a silent empty list.
        """
        params = {
            "domain": self.domain,
            "query": "isSuspended=true",
            "maxResults": DIRECTORY_PAGE_SIZE,
            "orderBy": "email",
            "projection": "basic",
        }
        users: list[dict] = []
        token = None
        pages = 0
        try:
            svc = self._directory_service()
            http = self._new_http(self._directory_creds)
            while True:
                resp = self._execute(lambda tok=token: svc.users().list(pageToken=tok, **params), http)
                users.extend(resp.get("users", []))
                token = resp.get("nextPageToken")
                pages += 1
                if not token or pages >= max_pages:
                    break
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] directory API error (users.list): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: DWD scope not granted for this client, or wrong subject.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (users.list): {type(e).__name__}") from e
        return users, bool(token)

    def list_user_oauth_tokens(self, user_key: str) -> list[dict]:
        """List third-party OAuth app grants for one user (Directory API ``tokens().list``).

        Single-user lookup, no pagination (the API returns the full grant list
        in one response). Read-only: only ``tokens().list`` is issued — never
        ``tokens().delete()``. Requires the ``admin.directory.user.security``
        DWD scope, distinct from ``admin.directory.user.readonly``; a missing
        grant surfaces as a permission error, never a silent empty list.
        """
        try:
            svc = self._directory_security_service()
            http = self._new_http(self._directory_security_creds)
            resp = self._execute(lambda: svc.tokens().list(userKey=user_key), http)
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] directory API error (tokens.list): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: DWD scope not granted for this client, or wrong subject.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (tokens.list): {type(e).__name__}") from e
        return resp.get("items", [])

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
