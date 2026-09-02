"""Configuration: per-domain service-account settings from an INI file.

No organization-specific value is hardcoded; everything comes from the file
pointed to by ``GWSADM_CONFIG`` (default ``~/.config/gwsadm-mcp/config.ini``)::

    [gwsadm]                                            ; optional
    internal_domains = example.edu, mail.example.edu    ; default: all [domain.*] names

    [domain.example.edu]
    service_account_file = /path/to/service-account.json
    subject = audit-admin@example.edu
    customer_id = C0xxxxxxx
    dmarc_rua_mailbox = postmaster@example.edu   ; optional, default: postmaster@<domain>; "none" opts out
    dmarc_rua_recipient = postmaster+rua@example.edu   ; optional, default: dmarc_rua_mailbox

Each ``[domain.*]`` section is one Google Workspace domain audited with its own
service account (domain-wide delegation) and impersonation subject.
``internal_domains`` is the allowlist used to classify sharing targets as
internal vs external.

``dmarc_rua_mailbox`` is the real user ``dmarc_rua_summary`` impersonates (domain-wide
delegation can only act as an actual user, never as a group or an alias) to read
DMARC aggregate reports. ``dmarc_rua_recipient`` is the address the reports are
actually sent to -- the ``rua=mailto:`` value published in the domain's ``_dmarc``
record -- and is used only to narrow the Gmail search (``to:<recipient>``). They
differ whenever the published address is a Gmail plus-subaddress
(``postmaster+rua@``: searching on it also keeps ``ruf=`` failure reports sent to
``postmaster+ruf@`` out of the aggregate parse) or a group that fans out to the
impersonated user's inbox. The recipient defaults to the mailbox, which is why the
zero-config default assumes ``postmaster@`` rather than requiring every deployment to
spell it out. Set ``dmarc_rua_mailbox = none`` to opt a domain out of DMARC reading
entirely -- e.g. when its ``rua=`` points at another domain's mailbox that a different
``[domain.*]`` section already reads (reports are grouped by the policy domain named
inside each report, so they still show up under that other section).
"""

import configparser
import os
from dataclasses import dataclass

DEFAULT_CONFIG = "~/.config/gwsadm-mcp/config.ini"


class ConfigError(Exception):
    """Raised when the config file is missing or incomplete."""


@dataclass(frozen=True)
class DomainConfig:
    """One audited Workspace domain (service account + impersonation subject)."""

    domain: str
    service_account_file: str
    subject: str
    customer_id: str
    # None = this domain opted out of DMARC reading (``dmarc_rua_mailbox = none``).
    dmarc_rua_mailbox: str | None
    # Address to search for (``to:``); None/unset = same as dmarc_rua_mailbox.
    dmarc_rua_recipient: str | None = None


def config_path() -> str:
    """Resolve the config path (GWSADM_CONFIG override, else the default)."""
    return os.path.expanduser(os.environ.get("GWSADM_CONFIG") or DEFAULT_CONFIG)


def load_config(path: str | None = None) -> tuple[list[DomainConfig], set[str]]:
    """Load domain configs and the internal-domain allowlist.

    Returns ``(domains, internal_domains)``. Raises ConfigError on a missing
    file, missing keys, or zero ``[domain.*]`` sections.
    """
    path = path or config_path()
    # Strip trailing ``# ...`` / ``; ...`` comments from values. Every example in
    # this docstring, the README and docs/setup annotates its keys that way, so
    # without this a copied line keeps the comment IN the value -- and the
    # failures are silent rather than loud: ``dmarc_rua_mailbox = none  # ...``
    # stops matching the opt-out sentinel and is treated as a literal mailbox,
    # and a commented ``dmarc_rua_recipient`` smuggles extra terms into the Gmail
    # search, returning an empty summary with no error. configparser only treats
    # a prefix as a comment when whitespace precedes it, so a value that legitimately
    # contains ``#``/``;`` mid-token (none do today) is left alone.
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    if not cp.read(path):
        raise ConfigError(f"config not found: {path} (set GWSADM_CONFIG)")
    domains: list[DomainConfig] = []
    for sec in cp.sections():
        if not sec.startswith("domain."):
            continue
        name = sec[len("domain.") :].strip().lower()
        # configparser section names are case-sensitive, so [domain.Example.edu]
        # and [domain.example.edu] are distinct sections that both land here as
        # "example.edu". Tools that pick one client per domain would silently
        # use whichever comes first (e.g. a stale key left from a rotation), so
        # fail loudly instead.
        if any(d.domain == name for d in domains):
            raise ConfigError(f"duplicate domain '{name}' in {path} (sections differing only in case?)")
        s = cp[sec]
        for key in ("service_account_file", "subject", "customer_id"):
            if not s.get(key, "").strip():
                raise ConfigError(f"[{sec}] is missing '{key}' in {path}")
        # Optional: unlike the three keys above, a domain with no DMARC tooling
        # need not set this. postmaster@ is RFC 2142's mandatory role mailbox,
        # so it is a safe zero-config default rather than a guess -- an org that
        # routes RUA reports elsewhere sets this explicitly instead. The literal
        # "none" (case-insensitive) opts the domain out: DWD cannot impersonate
        # a group/alias, so a domain whose rua= lands in another domain's
        # mailbox has nothing of its own to read.
        raw_mailbox = s.get("dmarc_rua_mailbox", "").strip()
        mailbox: str | None = None if raw_mailbox.lower() == "none" else (raw_mailbox or f"postmaster@{name}")
        recipient = s.get("dmarc_rua_recipient", "").strip()
        if recipient and mailbox is None:
            raise ConfigError(f"[{sec}] sets 'dmarc_rua_recipient' but 'dmarc_rua_mailbox = none' in {path}")
        domains.append(
            DomainConfig(
                domain=name,
                service_account_file=os.path.expanduser(s["service_account_file"].strip()),
                subject=s["subject"].strip(),
                customer_id=s["customer_id"].strip(),
                dmarc_rua_mailbox=mailbox,
                dmarc_rua_recipient=(recipient or mailbox),
            )
        )
    if not domains:
        raise ConfigError(f"no [domain.*] sections in {path}")
    raw = cp.get("gwsadm", "internal_domains", fallback="")
    internal = {x.strip().lower() for x in raw.split(",") if x.strip()}
    if not internal:
        internal = {d.domain for d in domains}
    return domains, internal


def is_external(address: str | None, internal_domains: set[str]) -> bool:
    """True when the address is outside the internal domains.

    Empty / malformed addresses (e.g. anonymous link access) count as external:
    for a security audit, "unknown" must not silently pass as internal.
    """
    if not address or "@" not in address:
        return True
    return address.rsplit("@", 1)[1].lower() not in internal_domains
