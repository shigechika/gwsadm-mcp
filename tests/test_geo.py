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


def test_damaged_deflate_stream_is_recorded_not_raised(tmp_path):
    good = tmp_path / "good.tsv.gz"
    with gzip.open(good, "wt", encoding="utf-8") as f:
        f.write(TABLE * 200)
    data = bytearray(good.read_bytes())
    for i in range(30, min(len(data) - 10, 400)):  # keep the header, wreck the compressed body
        data[i] ^= 0xFF
    bad = tmp_path / "bad.tsv.gz"
    bad.write_bytes(bytes(data))
    t = geo.load(env={geo.PATH_VAR: str(bad)})
    assert t.lookup(["2001:db8::1"]) == {}
    assert t.status()["error"] is not None


def test_health_sees_a_file_that_is_not_an_iptoasn_table(tmp_path):
    p = tmp_path / "x.tsv"
    p.write_text("hello world\n", encoding="utf-8")
    t = geo.load(env={geo.PATH_VAR: str(p), geo.HOME_VAR: "JP"})
    assert not t.usable and "5 tab-separated" in t.status()["error"]
    p2 = tmp_path / "y.tsv.gz"
    p2.write_bytes(b"plain text, not gzip")
    t2 = geo.load(env={geo.PATH_VAR: str(p2), geo.HOME_VAR: "JP"})
    assert not t2.usable and str(tmp_path) not in t2.status()["error"]


def test_missing_home_countries_is_a_warning(tmp_path):
    t = geo.load(env={geo.PATH_VAR: _table(tmp_path)})
    assert t.usable and "not set" in t.status()["warning"]


def test_a_non_ascii_digit_in_the_as_column_does_not_escape(tmp_path):
    p = tmp_path / "t.tsv"
    p.write_text("198.51.100.0\t198.51.100.255\t\u00b2\tJP\tX\n", encoding="utf-8")
    t = geo.load(env={geo.PATH_VAR: str(p), geo.HOME_VAR: "JP"})
    assert t.lookup(["198.51.100.20"]) == {}  # treated as unrouted, no ValueError


def test_probe_rejects_the_u32_variant(tmp_path):
    p = tmp_path / "u32.tsv"
    p.write_text("3325256704\t3325256959\t64500\tJP\tHOME-ISP\n", encoding="utf-8")
    t = geo.load(env={geo.PATH_VAR: str(p), geo.HOME_VAR: "JP"})
    assert not t.usable and "first column" in t.status()["error"]


def test_a_truncated_gzip_passes_the_probe_but_lookup_degrades(tmp_path):
    full = tmp_path / "full.tsv.gz"
    with gzip.open(full, "wt", encoding="utf-8") as f:
        f.write(
            "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n"
            + "".join(f"10.{i // 256}.{i % 256}.0\t10.{i // 256}.{i % 256}.255\t64500\tJP\tY\n" for i in range(20000))
        )
    data = full.read_bytes()
    cut = tmp_path / "cut.tsv.gz"
    cut.write_bytes(data[: len(data) // 2])  # the first line decompresses, the rest is missing
    t = geo.load(env={geo.PATH_VAR: str(cut), geo.HOME_VAR: "JP"})
    assert t.usable  # _probe reads one line only
    assert t.lookup(["198.51.100.1"]) == {}  # reaches the truncation: EOFError caught, not raised
    assert t.status()["error"] is not None and str(tmp_path) not in t.status()["error"]


def test_home_countries_warning_says_invalid_not_unset(tmp_path):
    p = tmp_path / "t.tsv"
    p.write_text(TABLE, encoding="utf-8")
    w = geo.load(env={geo.PATH_VAR: str(p), geo.HOME_VAR: "JP US"}).status()["warning"]
    assert "has no valid code" in w and "not set" not in w
