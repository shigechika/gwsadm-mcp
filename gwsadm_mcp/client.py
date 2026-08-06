"""Read-only Google Workspace Admin API client (service account + DWD).

One ``DomainClient`` per audited domain. Auth is a service account with
domain-wide delegation impersonating an audit-capable admin (``subject``) —
fully non-interactive, so the server can run unattended behind a gateway.

Read-only by design: only ``activities().list`` (Admin SDK Reports API),
``users().list`` (Directory API, for suspended-account snapshots),
``tokens().list`` (Directory API, for per-user OAuth app grants), and
``messages().list`` / ``messages().get`` (Gmail API, for message-trace) are
issued; no mutating call exists in this package.

Gmail access is architecturally different from the other three: those
impersonate one FIXED subject per domain (``cfg.subject``, the configured
audit admin) and are built once and cached for the domain's whole lifetime.
Gmail message-trace impersonates whichever RECIPIENT is being investigated —
a different subject on every call, unknowable in advance — so its
credentials/service are cached per user_email instead of once per domain
(see ``_gmail_service``).
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
# is NOT covered by admin.directory.user.readonly -- it needs this separate
# scope (a user's security/2SV/token resource). Credentials are built PER
# SCOPE (its own builder below, not one credentials object with all scopes)
# because a DWD token request is all-or-nothing over its scope list: a
# combined request fails entirely on a tenant that granted only one of the
# scopes, which would break the per-tool degradation the README promises
# (e.g. suspended_accounts must keep working when only the readonly grant
# exists). Do not merge the scope lists as a cleanup.
SCOPE_DIRECTORY_SECURITY = "https://www.googleapis.com/auth/admin.directory.user.security"
# gmail.readonly, not the narrower gmail.metadata: Gmail API's
# users.messages.list rejects the `q` search parameter under gmail.metadata
# (a documented, longstanding restriction, not an oversight here), and `q`
# is how message-trace finds a Message-ID without listing a user's entire
# mailbox. The tool code itself still only ever requests format="metadata"
# on messages().get() -- never the message body -- so what is actually
# READ stays narrow even though the DWD GRANT is broader than the other
# three scopes in this file.
SCOPE_GMAIL = "https://www.googleapis.com/auth/gmail.readonly"

# Reports API hard limit is 1000 per page.
PAGE_SIZE = 1000
# Directory API hard limit is 500 per page.
DIRECTORY_PAGE_SIZE = 500

# Per-request HTTP timeout (seconds).
_HTTP_TIMEOUT = 30
# Backoff-retry budget for rate-limit / transient server errors.
_MAX_RETRIES = 5
_MAX_BACKOFF = 8.0

# Cap on DomainClient._gmail_cache: unlike the other three services (one
# instance for cfg.subject, alive for the DomainClient's lifetime), this
# grows one entry per distinct recipient ever traced -- across a
# process-lifetime singleton reused over many separate gmail_message_trace
# calls investigating different incidents, that is otherwise unbounded.
# Evicted in FIFO order (oldest-built entry first) once the cap is hit; a
# re-traced recipient just rebuilds, at the cost of one extra credential
# build -- cheap next to the API calls each trace already makes.
_GMAIL_CACHE_MAX = 500


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
        gmail_service_factory=None,
    ):
        self.cfg = cfg
        self._reports = reports_service  # injectable for tests
        self._directory = directory_service  # injectable for tests
        self._directory_security = directory_security_service  # injectable for tests
        # injectable for tests: callable(user_email) -> a fake Gmail service,
        # bypassing real credential loading entirely (mirrors the *_service=
        # params above, but per-call rather than per-domain since the real
        # path below builds one client PER IMPERSONATED USER, not one for
        # the whole domain).
        self._gmail_service_factory = gmail_service_factory
        self._creds = None
        self._directory_creds = None
        self._directory_security_creds = None
        # user_email -> (creds, service). Unlike the other three services,
        # which cache one instance for cfg.subject and live for the
        # DomainClient's lifetime, this grows one entry per DISTINCT
        # recipient a caller has asked about, across every
        # gmail_message_trace call the process ever handles -- capped at
        # _GMAIL_CACHE_MAX with FIFO eviction (see _gmail_service).
        self._gmail_cache: dict[str, tuple] = {}
        # Guards the lazy build so concurrent fetch_activities() calls (the
        # parallel daily_brief) build the service/credentials at most once.
        self._build_lock = threading.Lock()
        self._gmail_cache_lock = threading.Lock()

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

    def _gmail_service(self, user_email: str):
        """Return (service, creds) for the Gmail API impersonating ONE user.

        Cached per ``user_email`` (see the class docstring for why this
        differs from the domain-fixed-subject services above). Building
        credentials does not itself contact Google or prove the DWD grant
        exists -- a bad/missing scope only surfaces once a request is
        actually issued, same as the other *_service methods.
        """
        if self._gmail_service_factory is not None:
            return self._gmail_service_factory(user_email), None
        with self._gmail_cache_lock:
            cached = self._gmail_cache.get(user_email)
            if cached is not None:
                return cached
        try:
            creds = service_account.Credentials.from_service_account_file(
                self.cfg.service_account_file, scopes=[SCOPE_GMAIL], subject=user_email
            )
        except (OSError, ValueError) as e:
            # See _reports_service: key path must not leak into tool output.
            raise GwsAuthError(f"[{self.domain}] cannot load service account key ({type(e).__name__})") from e
        svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
        with self._gmail_cache_lock:
            # Another thread may have built the same user's client while this
            # one was in flight; keep whichever landed in the cache first so
            # concurrent lookups for the same recipient converge on one
            # client rather than each holding their own.
            self._gmail_cache.setdefault(user_email, (svc, creds))
            if len(self._gmail_cache) > _GMAIL_CACHE_MAX:
                # dict iteration order is insertion order (Python 3.7+), so
                # the first key is the oldest entry -- plain FIFO, no access
                # tracking needed for a cap this generous.
                del self._gmail_cache[next(iter(self._gmail_cache))]
            return self._gmail_cache[user_email]

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
        filters: str | None = None,
        max_pages: int = 5,
    ) -> tuple[list[dict], bool]:
        """Fetch audit activities (newest first). Returns ``(items, capped)``.

        ``capped=True`` means more pages existed beyond ``max_pages`` — callers
        must surface this so a partial window is never mistaken for full coverage.
        ``filters`` is passed through as the Reports API ``filters`` expression
        (e.g. ``"doc_id==<id>"``); callers own validating any interpolated value
        because the expression is an operator language, not a plain string.
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
        if filters:
            params["filters"] = filters
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

    def find_message_by_id(self, user_email: str, message_id: str) -> dict | None:
        """Search one user's Gmail mailbox for an RFC 822 Message-ID.

        Impersonates ``user_email`` via domain-wide delegation (NOT
        ``cfg.subject`` — see the class docstring) and searches with
        ``q=rfc822msgid:<id>``, including SPAM and TRASH so a message that
        landed in either still counts as found. Requires the
        ``gmail.readonly`` DWD scope; ``gmail.metadata`` cannot run this
        query (Google restricts the ``q`` parameter to broader read scopes).

        Read-only: only ``messages().list`` and ``messages().get`` (with
        ``format="metadata"``, never ``"full"``/``"raw"``) are issued — the
        message body is never requested even though the granted scope would
        allow it.

        Returns ``None`` when no match exists in this mailbox (never
        delivered, or since deleted/expired — Gmail does not distinguish
        those from here). Otherwise a dict with ``label_ids`` (raw Gmail
        labels — check for ``"SPAM"``/``"TRASH"``/``"INBOX"`` to classify
        where it landed), ``thread_id``, ``snippet``, ``internal_date``
        (epoch ms, when Gmail received it), and ``headers`` (From/To/Cc/
        Subject/Date/Message-ID, flattened to a dict).
        """
        stripped = message_id.strip().strip("<>")
        query = f"rfc822msgid:{stripped}"
        try:
            svc, creds = self._gmail_service(user_email)
            http = self._new_http(creds)
            resp = self._execute(
                lambda: svc.users().messages().list(userId="me", q=query, includeSpamTrash=True, maxResults=5),
                http,
            )
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] gmail API error (messages.list, {user_email}): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: gmail.readonly DWD scope not granted for this client.
            raise GwsAuthError(f"[{self.domain}] auth failed for {user_email}: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (messages.list, {user_email}): {type(e).__name__}") from e

        matches = resp.get("messages", [])
        if not matches:
            return None
        # rfc822msgid is expected to be unique within one mailbox, but a
        # mailing-list + direct-CC delivery or a quarantine-release copy can
        # land two copies under the same Message-ID; take the first match
        # defensively rather than assume exactly one, and surface the count
        # so a caller sees when the answer is ambiguous rather than reading
        # a single silently-picked folder as authoritative.
        gmail_id = matches[0]["id"]
        try:
            msg = self._execute(
                lambda: (
                    svc.users()
                    .messages()
                    .get(
                        userId="me",
                        id=gmail_id,
                        format="metadata",
                        metadataHeaders=["From", "To", "Cc", "Subject", "Date", "Message-ID"],
                    )
                ),
                http,
            )
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] gmail API error (messages.get, {user_email}): HTTP {status}") from e
        except GoogleAuthError as e:
            # Same rationale as the list() call above: a scope/subject
            # problem can surface on either request sharing this creds/http.
            raise GwsAuthError(f"[{self.domain}] auth failed for {user_email}: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (messages.get, {user_email}): {type(e).__name__}") from e

        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", []) if "name" in h}
        return {
            "label_ids": msg.get("labelIds", []),
            "thread_id": msg.get("threadId"),
            "snippet": msg.get("snippet", ""),
            "internal_date": msg.get("internalDate"),
            "headers": headers,
            "match_count": len(matches),
        }

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
