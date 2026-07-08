"""Configuration: per-domain service-account settings from an INI file.

No organization-specific value is hardcoded; everything comes from the file
pointed to by ``GWSADM_CONFIG`` (default ``~/.config/gwsadm-mcp/config.ini``)::

    [gwsadm]                                            ; optional
    internal_domains = example.edu, mail.example.edu    ; default: all [domain.*] names

    [domain.example.edu]
    service_account_file = /path/to/service-account.json
    subject = audit-admin@example.edu
    customer_id = C0xxxxxxx

Each ``[domain.*]`` section is one Google Workspace domain audited with its own
service account (domain-wide delegation) and impersonation subject.
``internal_domains`` is the allowlist used to classify sharing targets as
internal vs external.
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


def config_path() -> str:
    """Resolve the config path (GWSADM_CONFIG override, else the default)."""
    return os.path.expanduser(os.environ.get("GWSADM_CONFIG") or DEFAULT_CONFIG)


def load_config(path: str | None = None) -> tuple[list[DomainConfig], set[str]]:
    """Load domain configs and the internal-domain allowlist.

    Returns ``(domains, internal_domains)``. Raises ConfigError on a missing
    file, missing keys, or zero ``[domain.*]`` sections.
    """
    path = path or config_path()
    cp = configparser.ConfigParser()
    if not cp.read(path):
        raise ConfigError(f"config not found: {path} (set GWSADM_CONFIG)")
    domains: list[DomainConfig] = []
    for sec in cp.sections():
        if not sec.startswith("domain."):
            continue
        name = sec[len("domain.") :].strip().lower()
        s = cp[sec]
        for key in ("service_account_file", "subject", "customer_id"):
            if not s.get(key, "").strip():
                raise ConfigError(f"[{sec}] is missing '{key}' in {path}")
        domains.append(
            DomainConfig(
                domain=name,
                service_account_file=os.path.expanduser(s["service_account_file"].strip()),
                subject=s["subject"].strip(),
                customer_id=s["customer_id"].strip(),
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
