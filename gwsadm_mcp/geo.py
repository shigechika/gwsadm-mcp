"""Attribute source IPs to a registered country and AS from a local iptoasn dataset.

The file is named by ``GWSADM_IP2ASN``: the "combined" table published by
iptoasn.com (PDDL), plain or gzip-compressed, one range per line::

    range_start <TAB> range_end <TAB> AS_number <TAB> country_code <TAB> AS_description

This server only reads the file; keeping it fresh is left to whatever already
maintains it on the host (a weekly download is plenty, registrations move
slowly). ``GWSADM_HOME_COUNTRIES`` (comma-separated ISO 3166-1 alpha-2 codes)
names the countries a change is expected to come from; without it a country is
still reported but nothing is called foreign.

Ranges are sorted by start within each address family, so the wanted addresses
are sorted the same way and matched in one streaming pass: a lookup for a few
dozen addresses reads the file once and holds none of it in memory. Ranges with
AS number 0 (not routed) leave an address unattributed. An IPv4-mapped IPv6
address is looked up as IPv4.
"""

from __future__ import annotations

import gzip
import ipaddress
import os
import re
import time
import zlib
from dataclasses import dataclass, field

PATH_VAR = "GWSADM_IP2ASN"
HOME_VAR = "GWSADM_HOME_COUNTRIES"
_CC_RE = re.compile(r"^[A-Z]{2}$")
# Reported, not enforced: an old file is still used, a stale one is called out in health_check.
STALE_DAYS = 30


@dataclass
class GeoTable:
    """Where the dataset is and which countries count as home, plus enough state for health_check."""

    path: str | None
    home: frozenset[str] = field(default_factory=frozenset)
    # error: the file cannot be used (no lookups). warning: something was ignored, lookups still work.
    error: str | None = None
    warning: str | None = None

    @property
    def configured(self) -> bool:
        """True when GWSADM_IP2ASN is set, whether or not the file is usable."""
        return bool(self.path)

    @property
    def usable(self) -> bool:
        return bool(self.path) and self.error is None

    def lookup(self, ips) -> dict[str, dict]:
        """Return ``{ip: {asn, cc, name}}`` for the addresses the dataset attributes.

        Addresses that do not parse, fall in an unrouted range, or are absent
        from the file are simply missing from the result. Never raises: an
        unreadable file is recorded in ``error`` and yields ``{}``.
        """
        if not self.usable:
            return {}
        want: dict[int, list[tuple[int, str]]] = {4: [], 6: []}
        for ip in set(ips):
            try:
                a = ipaddress.ip_address(ip)
            except (TypeError, ValueError):
                continue
            if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
                a = a.ipv4_mapped
            want[a.version].append((int(a), ip))
        if not (want[4] or want[6]):
            return {}
        for w in want.values():
            w.sort()
        ptr = {4: 0, 6: 0}
        found: dict[str, dict] = {}
        opener = gzip.open if self.path.endswith(".gz") else open
        try:
            with opener(self.path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if ptr[4] >= len(want[4]) and ptr[6] >= len(want[6]):
                        break
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 5:
                        continue
                    # The family is visible without parsing; skip a family already matched out
                    # (the table holds hundreds of thousands of ranges, most of them IPv4).
                    ver = 6 if ":" in parts[0] else 4
                    if ptr[ver] >= len(want[ver]):
                        continue
                    try:
                        lo, hi = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    if lo.version != ver:
                        continue
                    w = want[ver]
                    i, lo_i, hi_i = ptr[ver], int(lo), int(hi)
                    while i < len(w) and w[i][0] < lo_i:
                        i += 1
                    while i < len(w) and w[i][0] <= hi_i:
                        asn = int(parts[2]) if parts[2].isdigit() else 0
                        cc = parts[3].strip().upper()
                        if asn:
                            found[w[i][1]] = {
                                "asn": asn,
                                "cc": cc if _CC_RE.match(cc) else None,
                                "name": parts[4][:120],
                            }
                        i += 1
                    ptr[ver] = i
        except (OSError, EOFError, gzip.BadGzipFile, zlib.error) as e:
            self.error = f"cannot read {PATH_VAR}: {type(e).__name__}"
            return {}
        return found

    def status(self) -> dict:
        """Fixed-shape summary for health_check and tool output."""
        age = None
        if self.path:
            try:
                age = round((time.time() - os.path.getmtime(self.path)) / 86400, 1)
            except OSError:
                age = None
        warning = self.warning
        if age is not None and age > STALE_DAYS:
            warning = f"{PATH_VAR} is {age} days old (refresh it)" + (f"; {warning}" if warning else "")
        return {
            "configured": self.configured,
            "home_countries": sorted(self.home),
            "age_days": age,
            "error": self.error,
            "warning": warning,
        }


def load(env: dict | None = None) -> GeoTable:
    """Read the two variables; check the file exists and the home codes are well formed."""
    e = os.environ if env is None else env
    path = e.get(PATH_VAR) or None
    raw = [c.strip().upper() for c in (e.get(HOME_VAR) or "").split(",") if c.strip()]
    bad = [c for c in raw if not _CC_RE.match(c)]
    table = GeoTable(path=path, home=frozenset(c for c in raw if _CC_RE.match(c)))
    if path:
        table.error = _probe(path)
    warnings = []
    if bad:
        warnings.append(f"{HOME_VAR} has codes that are not ISO 3166-1 alpha-2, ignored: {', '.join(bad[:5])}")
    if path and not table.home:
        warnings.append(f"{HOME_VAR} is not set: countries are reported but none is called foreign")
    table.warning = "; ".join(warnings) or None
    return table


def _probe(path: str) -> str | None:
    """Read the first line, so health_check sees an unreadable or non-gzip file before a lookup does."""
    if not os.path.isfile(path):
        return f"cannot read {PATH_VAR}: no such file"
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            first = f.readline()
    except (OSError, EOFError, gzip.BadGzipFile, zlib.error) as e:
        # Type name only: OSError messages embed the path.
        return f"cannot read {PATH_VAR}: {type(e).__name__}"
    if first.count("\t") < 4:
        return f"{PATH_VAR} does not look like an iptoasn table (expected 5 tab-separated columns)"
    return None
