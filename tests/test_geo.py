"""Tests for the iptoasn country attribution (gwsadm_mcp.geo)."""

import gzip

from gwsadm_mcp import geo

TABLE = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    "198.51.100.0\t198.51.100.255\t64500\tJP\tHOME-ISP\n"
    "203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n"
    "2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64502\tJP\tHOME-V6\n"
)


def _table(tmp_path, gz=False):
    p = tmp_path / ("t.tsv.gz" if gz else "t.tsv")
    if gz:
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write(TABLE)
    else:
        p.write_text(TABLE, encoding="utf-8")
    return str(p)


def test_unconfigured_reports_and_looks_up_nothing():
    t = geo.load(env={})
    assert t.status() == {"configured": False, "home_countries": [], "age_days": None, "error": None, "warning": None}
    assert t.lookup(["198.51.100.1"]) == {}


def test_lookup_plain_and_gzip_v4_v6_and_mapped(tmp_path):
    for gz in (False, True):
        t = geo.load(env={geo.PATH_VAR: _table(tmp_path, gz), geo.HOME_VAR: "jp"})
        got = t.lookup(["198.51.100.7", "2001:db8::1", "::ffff:1.0.0.9", "203.0.113.5", "not-an-ip", "8.8.8.8"])
        assert got["198.51.100.7"]["cc"] == "JP" and got["198.51.100.7"]["asn"] == 64500
        assert got["2001:db8::1"]["name"] == "HOME-V6"
        assert got["::ffff:1.0.0.9"]["cc"] == "US"
        assert "203.0.113.5" not in got  # unrouted (AS 0)
        assert "8.8.8.8" not in got and "not-an-ip" not in got
        assert t.home == frozenset({"JP"})


def test_missing_file_is_an_error_and_never_raises(tmp_path):
    t = geo.load(env={geo.PATH_VAR: str(tmp_path / "nope.tsv")})
    assert t.configured and not t.usable and "no such file" in t.status()["error"]
    assert str(tmp_path) not in t.status()["error"]  # the path is not echoed
    assert t.lookup(["198.51.100.7"]) == {}


def test_bad_home_codes_are_a_warning_not_an_error(tmp_path):
    t = geo.load(env={geo.PATH_VAR: _table(tmp_path), geo.HOME_VAR: "JP, Japan, U1"})
    st = t.status()
    assert t.usable and t.home == frozenset({"JP"})
    assert st["error"] is None and "JAPAN" in st["warning"] and "U1" in st["warning"]


def test_corrupt_gzip_is_recorded_not_raised(tmp_path):
    p = tmp_path / "bad.tsv.gz"
    p.write_bytes(b"not gzip at all")
    t = geo.load(env={geo.PATH_VAR: str(p)})
    assert t.lookup(["198.51.100.7"]) == {}
    assert t.status()["error"] is not None and str(p) not in t.status()["error"]
