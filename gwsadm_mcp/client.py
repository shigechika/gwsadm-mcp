"""Read-only Google Workspace Admin API client (service account + DWD).

One ``DomainClient`` per audited domain. Auth is a service account with
domain-wide delegation impersonating an audit-capable admin (``subject``) —
fully non-interactive, so the server can run unattended behind a gateway.

Read-only by design: only ``activities().list`` (Admin SDK Reports API),
``users().list`` (Directory API, for suspended-account snapshots),
``users().get`` (Directory API, for a single account's state),
``tokens().list`` (Directory API, for per-user OAuth app grants),
``messages().list`` / ``messages().get`` (Gmail API, for message-trace),
``groups().get`` (Groups Settings API, for a group's own posting policy), and
``groups().get`` / ``members().list`` (Directory API, for a group's roster)
are issued; no mutating call exists in this package.

Gmail access is architecturally different from the other services: it
impersonates whichever RECIPIENT is being investigated -- a different
subject on every call, unknowable in advance -- while every other service
(Reports, both Directory scopes, Groups Settings, both group scopes)
impersonates one FIXED subject per domain (``cfg.subject``, the configured
audit admin) and is built once and cached for the domain's whole lifetime.
Gmail's credentials/service are cached per user_email instead
(see ``_gmail_service``).
"""

import base64
import binascii
import concurrent.futures
import datetime
import gzip
import io
import random
import threading
import time
import xml.etree.ElementTree as ET
import zipfile

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
# Groups Settings is a distinct API/product from the Directory API scopes
# below -- it answers "what is this group's own access-control policy"
# (who_can_post, allow_external_members, moderation), not "who is in it".
# No readonly variant exists for this scope (Google has never split one out).
SCOPE_GROUPS_SETTINGS = "https://www.googleapis.com/auth/apps.groups.settings"
SCOPE_DIRECTORY_GROUP = "https://www.googleapis.com/auth/admin.directory.group.readonly"
SCOPE_DIRECTORY_GROUP_MEMBER = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"

# Reports API hard limit is 1000 per page.
PAGE_SIZE = 1000
# Directory API hard limit is 500 per page (users().list()).
DIRECTORY_PAGE_SIZE = 500
# Directory API members().list() has a LOWER hard limit than users().list()
# above (200, not 500) -- a separate constant, not a shared one, so a future
# change to one does not silently mis-page the other.
GROUP_MEMBER_PAGE_SIZE = 200

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

# messages().list page size for a Message-ID search. rfc822msgid is expected
# to return at most a small handful of matches even in the ambiguous case
# (see find_message_by_id), so this is a safety bound, not a real page size
# -- but it means a mailbox with MORE matches than this only returns a
# partial page, since this call does not paginate. find_message_by_id
# detects that from Gmail's own "nextPageToken" (NOT from
# len(matches) >= this constant, which is also true of a mailbox with
# EXACTLY this many matches and nothing more) and sets match_count_capped.
_MESSAGE_LIST_MAX_RESULTS = 5

# messages().list page size for a DMARC RUA mailbox search. Gmail's hard cap
# is 500; kept far below that so one page's worth of per-message fetches
# (see fetch_dmarc_rua_records) stays a bounded, predictable unit of work
# rather than a single 500-message batch.
_DMARC_MESSAGE_LIST_PAGE_SIZE = 100

# Bounded worker count for fetching+parsing one page's messages concurrently
# in fetch_dmarc_rua_records. Doing this serially is what made an earlier
# ad-hoc script (a personal-account Python loop, not this server) take
# several minutes for ~200 messages -- two Gmail API round trips each, one
# at a time. This mirrors the boxadm-mcp _SCAN_CONCURRENCY_DEFAULT rationale:
# I/O-bound work, a handful of concurrent requests captures most of the win
# without provoking per-user Gmail API rate limits.
_DMARC_FETCH_WORKERS_DEFAULT = 8


def _find_attachment_id(payload: dict) -> str | None:
    """Depth-first search of a Gmail message payload for the first attachment id.

    A DMARC RUA report email is near-universally a single attachment (the
    compressed report XML) with no other parts worth inspecting, so the
    first attachment found is taken without disambiguating multi-attachment
    messages -- an RUA sender that also attaches something else is not a
    case this has ever needed to handle.
    """
    attachment_id = payload.get("body", {}).get("attachmentId")
    if attachment_id:
        return attachment_id
    for part in payload.get("parts", []) or []:
        found = _find_attachment_id(part)
        if found:
            return found
    return None


def _decode_report_payload(raw: bytes) -> bytes:
    """Decompress a DMARC aggregate-report attachment.

    RUA senders overwhelmingly gzip the report XML (the RFC 7489-recommended
    form); a shrinking minority zip it instead. Anything that is neither is
    returned as-is on the assumption it is already plain XML -- the caller's
    XML parse is what actually validates that assumption, not this function.
    """
    try:
        return gzip.decompress(raw)
    except OSError:
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            return zf.read(zf.namelist()[0])
    except zipfile.BadZipFile:
        return raw


def _parse_dmarc_records(xml_bytes: bytes) -> list[dict]:
    """Parse one DMARC aggregate-report XML document into its per-source-IP records.

    Each returned dict is ``{policy_domain, source_ip, count, dkim, spf,
    disposition, header_from}`` -- the raw fields a caller needs to judge
    DMARC pass/fail correctly. This function does NOT itself decide
    pass/fail: ``dkim``/``spf`` here are Google's *aligned* policy_evaluated
    values, and a record with EITHER one (not necessarily both) reading
    "pass" is a DMARC pass -- treating any non-"pass" dkim as a failure
    regardless of spf overcounts dramatically, since a lot of legitimate
    mail passes DMARC via SPF alignment alone. That judgment belongs to the
    caller (see ``server.py``'s aggregation), which is also better placed to
    decide what "reject candidate" means for its own purposes.

    A ``<record>`` with a missing/unparsable ``<count>`` is skipped rather
    than raising: one malformed record in an otherwise-valid report must not
    lose every other record in it.
    """
    root = ET.fromstring(xml_bytes)
    policy_domain = root.findtext(".//policy_published/domain") or ""
    records: list[dict] = []
    for rec in root.findall(".//record"):
        count_text = rec.findtext("row/count")
        try:
            count = int(count_text) if count_text is not None else None
        except ValueError:
            count = None
        if count is None:
            continue
        records.append(
            {
                "policy_domain": policy_domain,
                "source_ip": rec.findtext("row/source_ip") or "",
                "count": count,
                "dkim": rec.findtext("row/policy_evaluated/dkim") or "",
                "spf": rec.findtext("row/policy_evaluated/spf") or "",
                "disposition": rec.findtext("row/policy_evaluated/disposition") or "",
                "header_from": rec.findtext(".//identifiers/header_from") or "",
            }
        )
    return records


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


def _is_not_found(e: HttpError) -> bool:
    """True for a plain HTTP 404 -- the key does not name any such resource in
    this domain (verified live for the three group lookups:
    groupssettings.groups().get, directory.groups().get, and
    directory.members().list all return exactly this for a nonexistent group,
    not e.g. 400). ``directory.users().get`` is documented to answer an
    unknown ``userKey`` the same way and is read here on that basis, not on a
    live check of this tenant -- the smoke probe in ``scripts/smoke_probes.py``
    looks up a synthetic address against the real tenant, so a run of that is
    what would catch a different status. Distinct from every other HttpError,
    which stays a real ``GwsError`` -- a caller must be able to tell "this
    doesn't exist" (a normal, expected answer) apart from "the API call itself
    failed" (a real problem)."""
    status = getattr(getattr(e, "resp", None), "status", None)
    return status == 404


def _settings_bool(v) -> bool | None:
    """Groups Settings API booleans are the STRINGS "true"/"false", not JSON
    booleans (a longstanding quirk of this older REST API) -- normalize so
    tool output carries real booleans instead of leaking that quirk to callers."""
    if v is None:
        return None
    return str(v).strip().lower() == "true"


class DomainClient:
    """Audit-activities client for one Workspace domain."""

    def __init__(
        self,
        cfg: DomainConfig,
        *,
        reports_service=None,
        directory_service=None,
        directory_security_service=None,
        groups_settings_service=None,
        directory_group_service=None,
        directory_group_member_service=None,
        gmail_service_factory=None,
    ):
        self.cfg = cfg
        self._reports = reports_service  # injectable for tests
        self._directory = directory_service  # injectable for tests
        self._directory_security = directory_security_service  # injectable for tests
        self._groups_settings = groups_settings_service  # injectable for tests
        self._directory_group = directory_group_service  # injectable for tests
        self._directory_group_member = directory_group_member_service  # injectable for tests
        # injectable for tests: callable(user_email) -> a fake Gmail service,
        # bypassing real credential loading entirely (mirrors the *_service=
        # params above, but per-call rather than per-domain since the real
        # path below builds one client PER IMPERSONATED USER, not one for
        # the whole domain).
        self._gmail_service_factory = gmail_service_factory
        self._creds = None
        self._directory_creds = None
        self._directory_security_creds = None
        self._groups_settings_creds = None
        self._directory_group_creds = None
        self._directory_group_member_creds = None
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

    def _groups_settings_service(self):
        if self._groups_settings is None:
            with self._build_lock:
                if self._groups_settings is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file, scopes=[SCOPE_GROUPS_SETTINGS], subject=self.cfg.subject
                        )
                    except (OSError, ValueError) as e:
                        # See _reports_service: key path must not leak into tool output.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._groups_settings_creds = creds
                    self._groups_settings = build("groupssettings", "v1", credentials=creds, cache_discovery=False)
        return self._groups_settings

    def _directory_group_service(self):
        if self._directory_group is None:
            with self._build_lock:
                if self._directory_group is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file, scopes=[SCOPE_DIRECTORY_GROUP], subject=self.cfg.subject
                        )
                    except (OSError, ValueError) as e:
                        # See _reports_service: key path must not leak into tool output.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._directory_group_creds = creds
                    self._directory_group = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        return self._directory_group

    def _directory_group_member_service(self):
        if self._directory_group_member is None:
            with self._build_lock:
                if self._directory_group_member is None:  # re-check under lock
                    try:
                        creds = service_account.Credentials.from_service_account_file(
                            self.cfg.service_account_file,
                            scopes=[SCOPE_DIRECTORY_GROUP_MEMBER],
                            subject=self.cfg.subject,
                        )
                    except (OSError, ValueError) as e:
                        # See _reports_service: key path must not leak into tool output.
                        raise GwsAuthError(
                            f"[{self.domain}] cannot load service account key ({type(e).__name__})"
                        ) from e
                    self._directory_group_member_creds = creds
                    self._directory_group_member = build(
                        "admin", "directory_v1", credentials=creds, cache_discovery=False
                    )
        return self._directory_group_member

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

    def get_user(self, user_key: str) -> dict | None:
        """Fetch ONE user's account record (Directory API ``users().get``).

        The per-account counterpart to ``list_suspended_users``. That method
        cannot answer "is THIS account suspended?" at all: it queries
        ``isSuspended=true``, so a non-suspended account is filtered out
        server-side and can never appear at any page count -- and when the
        suspended set itself exceeds the page cap, "absent" stops being
        evidence even for a suspended one. This is one request, no pagination,
        for a caller who already knows the address.

        Shares ``list_suspended_users``' DWD scope exactly --
        ``admin.directory.user.readonly`` covers ``users().get`` (checked
        against the Directory API's own discovery document, which lists that
        scope on ``directory.users.get``) -- so this deliberately reuses the
        same lazily-built, per-domain-cached ``_directory_service()`` rather
        than adding another credential object and another grant to provision:
        a tenant already running ``suspended_accounts`` needs no new scope.

        Read-only: only ``users().get()`` is issued, never a mutating method.
        ``projection="basic"`` matches ``list_suspended_users``, pinning the
        response to the standard fields -- a tenant with large custom user
        schemas must not have them pulled into an audit answer that has no
        use for them.

        Returns the raw user resource, or ``None`` when ``user_key`` does not
        name a user in this tenant (a plain HTTP 404) -- a typo'd or deleted
        address is a normal, expected answer and is itself diagnostic, so it
        must stay distinguishable from a raised ``GwsError``/``GwsAuthError``,
        which mean the call failed and say nothing about whether the account
        exists.
        """
        try:
            svc = self._directory_service()
            http = self._new_http(self._directory_creds)
            resp = self._execute(lambda: svc.users().get(userKey=user_key, projection="basic"), http)
        except HttpError as e:
            if _is_not_found(e):
                return None
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] directory API error (users.get): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: DWD scope not granted for this client, or wrong subject.
            #
            # Keeping the message is a deliberate call, not the accidental one
            # REVIEW.md warns about: the message names WHICH grant is missing,
            # which is the whole diagnostic. What can reach here is bounded --
            # a key file that cannot be read or parsed raises OSError/ValueError
            # inside _directory_service(), which already reduces it to the
            # exception type precisely because it embeds the key path, so this
            # handler only ever sees a refresh/transport failure whose text is
            # the token endpoint's own response (e.g. "unauthorized_client").
            # Same call, for the same reason, as the two existing sites above.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (users.get): {type(e).__name__}") from e
        return resp

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
        (epoch ms, when Gmail received it), ``headers`` (From/To/Cc/
        Subject/Date/Message-ID, flattened to a dict), ``match_count`` (see
        the mailing-list/direct-CC note above), and ``match_count_capped``
        (true when Gmail's own ``nextPageToken`` says more matches exist
        beyond this page — ``match_count`` is a lower bound in that case,
        not exact, since this call does not paginate).
        """
        stripped = message_id.strip().strip("<>")
        query = f"rfc822msgid:{stripped}"
        try:
            svc, creds = self._gmail_service(user_email)
            http = self._new_http(creds)
            resp = self._execute(
                lambda: (
                    svc.users()
                    .messages()
                    .list(userId="me", q=query, includeSpamTrash=True, maxResults=_MESSAGE_LIST_MAX_RESULTS)
                ),
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
            # A "nextPageToken" in the response is Gmail's own signal that
            # more results exist beyond this page -- NOT len(matches) >=
            # _MESSAGE_LIST_MAX_RESULTS, which is also true, wrongly, of a
            # mailbox with EXACTLY that many matches and nothing more (that
            # response omits nextPageToken). This call does not paginate, so
            # when the token is present match_count is a lower bound, not
            # the true count.
            "match_count_capped": bool(resp.get("nextPageToken")),
        }

    def fetch_dmarc_rua_records(
        self,
        *,
        start: datetime.datetime,
        mailbox: str | None = None,
        max_pages: int = 5,
        max_workers: int = _DMARC_FETCH_WORKERS_DEFAULT,
    ) -> tuple[list[dict], bool, int, str]:
        """Fetch and parse DMARC aggregate (RUA) reports delivered to one mailbox.

        Impersonates ``mailbox`` (default ``cfg.dmarc_rua_mailbox``) via the
        same ``gmail.readonly`` DWD scope and per-user credential cache as
        ``find_message_by_id`` -- see the class docstring for why Gmail auth
        is architecturally different from this client's other services.

        Searches for messages addressed to ``mailbox`` received on or after
        ``start`` (Gmail's ``after:`` search operator, second-precision unix
        timestamp), then for each matching message walks its MIME parts for
        the first attachment, decompresses it, and parses every ``<record>``
        element -- see ``_find_attachment_id``/``_decode_report_payload``/
        ``_parse_dmarc_records``. A message with no attachment, or whose
        attachment fails to decode or parse, is skipped and counted in the
        returned message-error count rather than aborting the whole fetch --
        one malformed report must not blind the caller to every other report
        in the window.

        Per-page message fetches run concurrently (bounded by ``max_workers``)
        because this step is two Gmail API round trips PER MESSAGE
        (``messages().get`` then ``attachments().get``) with no server-side
        aggregation to fall back on -- doing this serially made a comparable
        ad-hoc script take minutes for ~200 messages, which risks outrunning
        an MCP client's own gateway timeout. Each worker builds its own
        ``httplib2.Http`` (see ``_new_http``'s docstring on why one instance
        cannot be shared across threads).

        Read-only: only ``messages().list``, ``messages().get`` (``format=
        "full"`` -- the only way to see attachment ids; there is no way to
        fetch just the MIME tree without headers too) and
        ``messages().attachments().get`` are issued.

        Returns ``(records, capped, message_errors, mailbox)`` -- the last is
        the mailbox actually used (the resolved ``cfg.dmarc_rua_mailbox``
        default when the ``mailbox`` argument was not given), so a caller can
        report which address the summary covers without reaching into this
        client's config. ``capped=True`` means the mailbox had more pages of
        matching messages than ``max_pages`` covered -- unlike
        ``fetch_activities``, every matching message must be walked (there is
        no server-side count to report instead), so a capped fetch
        under-counts real report volume, not just a lower bound on some other
        total.
        """
        mailbox = mailbox or self.cfg.dmarc_rua_mailbox
        svc, creds = self._gmail_service(mailbox)
        list_http = self._new_http(creds)
        query = f"to:{mailbox} after:{int(start.timestamp())}"

        def _fetch_one(message_id: str) -> list[dict] | None:
            """Fetch+parse one message's attachment; None on a tolerated per-message failure."""
            http = self._new_http(creds)
            full = self._execute(lambda: svc.users().messages().get(userId="me", id=message_id, format="full"), http)
            attachment_id = _find_attachment_id(full.get("payload", {}))
            if not attachment_id:
                return None
            att = self._execute(
                lambda: svc.users().messages().attachments().get(userId="me", messageId=message_id, id=attachment_id),
                http,
            )
            data = att.get("data") or ""
            if not data:
                return None
            padded = data + "=" * (-len(data) % 4)
            xml_bytes = _decode_report_payload(base64.urlsafe_b64decode(padded))
            return _parse_dmarc_records(xml_bytes)

        records: list[dict] = []
        message_errors = 0
        token = None
        pages = 0
        try:
            while True:
                resp = self._execute(
                    lambda tok=token: (
                        svc.users()
                        .messages()
                        .list(userId="me", q=query, maxResults=_DMARC_MESSAGE_LIST_PAGE_SIZE, pageToken=tok)
                    ),
                    list_http,
                )
                message_ids = [m["id"] for m in resp.get("messages", [])]
                if message_ids:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(message_ids))) as ex:
                        futs = [ex.submit(_fetch_one, mid) for mid in message_ids]
                        for fut in concurrent.futures.as_completed(futs):
                            # HttpError/transport/parse failures on ONE message are
                            # tolerated (counted, not raised). A GoogleAuthError is
                            # NOT in this tuple -- it isn't a subclass of any of these
                            # (verified: GoogleAuthError.__mro__ is (..., Exception,
                            # BaseException, object), no OSError/HttpError in it) -- so
                            # it propagates out of fut.result() uncaught, out of this
                            # loop, to the outer `except GoogleAuthError` below. That is
                            # deliberate: the whole mailbox/scope is broken identically
                            # for every message, so it should fail the fetch outright
                            # instead of being silently counted as hundreds of
                            # individual message errors.
                            try:
                                result = fut.result()
                            except (HttpError, httplib2.HttpLib2Error, OSError, ET.ParseError, binascii.Error):
                                message_errors += 1
                                continue
                            if result is None:
                                message_errors += 1
                            else:
                                records.extend(result)
                token = resp.get("nextPageToken")
                pages += 1
                if not token or pages >= max_pages:
                    break
        except HttpError as e:
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] gmail API error (messages.list, {mailbox}): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: gmail.readonly DWD scope not granted for this client, or a
            # per-message auth failure re-raised from the worker loop above.
            raise GwsAuthError(f"[{self.domain}] auth failed for {mailbox}: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (gmail, {mailbox}): {type(e).__name__}") from e
        return records, bool(token), message_errors, mailbox

    def get_group_settings(self, group_email: str) -> dict | None:
        """Fetch one Google Group's own posting/delivery policy (Groups Settings API).

        A Group's access-control layer sits IN FRONT of Gmail delivery: when
        ``who_can_post`` restricts posting to domain members/group members
        only, an external sender's message is rejected there and never
        generates a per-recipient Gmail delivery event at all -- so
        ``find_message_by_id``/the Reports API ``applicationName=gmail`` event
        stream both see nothing for that address, not a bounce. This method
        reads the policy directly instead of it having to be inferred from an
        absence of delivery events (see ``docs`` for the incident this was
        built from: two G Suite groups accepted a normal internal newsletter
        but silently dropped the same message from an external sender,
        indistinguishable from a delivery failure without this).

        Read-only: only ``groups().get()`` is issued. Requires the
        ``apps.groups.settings`` DWD scope -- a distinct API/product from the
        Directory API scopes ``get_group``/``list_group_members`` use, so
        either can be granted without the other.

        Returns ``None`` when ``group_email`` does not name any group in this
        domain (a plain HTTP 404, verified against production) -- a normal,
        expected answer distinguished from a raised ``GwsError``/``GwsAuthError``,
        which mean the call itself failed to work.
        """
        try:
            svc = self._groups_settings_service()
            http = self._new_http(self._groups_settings_creds)
            resp = self._execute(lambda: svc.groups().get(groupUniqueId=group_email), http)
        except HttpError as e:
            if _is_not_found(e):
                return None
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] groups settings API error (groups.get): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: apps.groups.settings DWD scope not granted for this client.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (groups.get): {type(e).__name__}") from e
        return {
            "who_can_post": resp.get("whoCanPostMessage"),
            "allow_external_members": _settings_bool(resp.get("allowExternalMembers")),
            "is_archived": _settings_bool(resp.get("isArchived")),
            "message_moderation_level": resp.get("messageModerationLevel"),
            "spam_moderation_level": resp.get("spamModerationLevel"),
            "allow_web_posting": _settings_bool(resp.get("allowWebPosting")),
        }

    def get_group(self, group_email: str) -> dict | None:
        """Fetch one Google Group's basic metadata (Directory API ``groups().get()``).

        Deliberately independent of ``list_group_members`` below (not a
        combined list-then-get like ``find_message_by_id``): the two calls
        use DIFFERENT DWD scopes (``admin.directory.group.readonly`` here vs
        ``admin.directory.group.member.readonly`` there) that are granted
        separately in practice, so neither call's success may gate the
        other's — a tenant that granted only one scope must still get that
        one piece, and a caller wanting both issues both calls itself (see
        the ``list_group_members`` MCP tool in ``server.py``).

        Read-only: only ``groups().get()`` is issued.

        Returns ``None`` when ``group_email`` does not name any group in this
        domain (a plain HTTP 404, verified against production) -- a normal,
        expected answer distinguished from a raised ``GwsError``/``GwsAuthError``.
        """
        try:
            svc = self._directory_group_service()
            http = self._new_http(self._directory_group_creds)
            resp = self._execute(lambda: svc.groups().get(groupKey=group_email), http)
        except HttpError as e:
            if _is_not_found(e):
                return None
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] directory API error (groups.get): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: admin.directory.group.readonly DWD scope not granted.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (groups.get): {type(e).__name__}") from e
        return {
            "email": resp.get("email"),
            "name": resp.get("name"),
            "description": resp.get("description"),
            "direct_members_count": resp.get("directMembersCount"),
        }

    def list_group_members(self, group_email: str, *, max_pages: int = 20) -> tuple[list[dict], bool] | None:
        """Fetch a Google Group's member roster, paginated (Directory API ``members().list()``).

        Resolves membership directly -- unlike inferring it from Reports API
        delivery-event fanout (``applicationName=gmail``), which only shows
        members who actually received one PARTICULAR message and requires one
        to already have been sent. Independent of ``get_group`` above — see
        its docstring for why neither call gates the other. Read-only, never
        a mutating call. Requires the ``admin.directory.group.member.readonly``
        DWD scope.

        Returns ``(members, capped)``, or ``None`` when ``group_email`` does
        not name any group in this domain (a plain HTTP 404 on the FIRST
        page, verified against production) -- a normal, expected answer
        distinguished from a raised ``GwsError``/``GwsAuthError``.
        ``capped=True`` means more pages existed beyond ``max_pages``
        (Directory API hard limit ``GROUP_MEMBER_PAGE_SIZE`` per page) -- a
        caller must not mistake a partial roster for the full one.
        """
        members: list[dict] = []
        token = None
        pages = 0
        try:
            svc = self._directory_group_member_service()
            http = self._new_http(self._directory_group_member_creds)
            while True:
                resp = self._execute(
                    lambda tok=token: svc.members().list(
                        groupKey=group_email, maxResults=GROUP_MEMBER_PAGE_SIZE, pageToken=tok
                    ),
                    http,
                )
                members.extend(resp.get("members", []))
                token = resp.get("nextPageToken")
                pages += 1
                if not token or pages >= max_pages:
                    break
        except HttpError as e:
            if pages == 0 and _is_not_found(e):
                # 404 on the very first page: the group itself doesn't exist.
                # A 404 on a LATER page (a group that existed when listing
                # started but was deleted mid-pagination) is not this --
                # that stays a real GwsError below rather than silently
                # reporting a partial roster as "not found".
                return None
            status = getattr(e, "status_code", None) or getattr(getattr(e, "resp", None), "status", "?")
            raise GwsError(f"[{self.domain}] directory API error (members.list): HTTP {status}") from e
        except GoogleAuthError as e:
            # Typical: admin.directory.group.member.readonly DWD scope not granted.
            raise GwsAuthError(f"[{self.domain}] auth failed: {e}") from e
        except (httplib2.HttpLib2Error, OSError) as e:
            raise GwsError(f"[{self.domain}] transport error (members.list): {type(e).__name__}") from e
        return [
            {"email": m.get("email"), "role": m.get("role"), "type": m.get("type"), "status": m.get("status")}
            for m in members
        ], bool(token)

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
