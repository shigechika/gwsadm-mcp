"""Entry-point behavior: interactive ^C must exit cleanly (no traceback)."""

import signal
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT semantics differ on Windows")
def test_sigint_exits_cleanly():
    p = subprocess.Popen(
        [sys.executable, "-m", "gwsadm_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2.0)  # let the stdio server start
    p.send_signal(signal.SIGINT)
    out, err = p.communicate(timeout=10)
    assert p.returncode == 0
    assert b"Traceback" not in err


def test_dmarc_reports_cli(monkeypatch, capsysbinary):
    import json

    import gwsadm_mcp.client as client
    import gwsadm_mcp.config as config
    from gwsadm_mcp import __main__ as cli
    from gwsadm_mcp.config import DomainConfig

    cfg = DomainConfig("example.edu", "/tmp/sa.json", "a@example.edu", "C0abc", "postmaster@example.edu")
    monkeypatch.setattr(config, "load_config", lambda: ([cfg], set()))
    seen = {}

    def fake_fetch(self, *, start, end, max_pages):
        seen.update(start=start, end=end, max_pages=max_pages)
        return {
            "reports": [{"org_name": "用例.example", "report_id": "1", "records": []}],
            "messages": 1,
            "capped": False,
            "message_errors": 0,
            "non_report_attachments": 0,
            "dropped_records": 0,
            "mailbox": cfg.dmarc_rua_mailbox,
            "recipient": cfg.dmarc_rua_mailbox,
        }

    monkeypatch.setattr(client.DomainClient, "fetch_dmarc_reports", fake_fetch)
    monkeypatch.setattr(
        "sys.argv",
        ["gwsadm-mcp", "dmarc-reports", "--domain", "example.edu", "--since", "2026-09-20", "--until", "2026-09-23"],
    )
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 0
    out = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert out["fetch_complete"] is True and out["reports"][0]["org_name"] == "用例.example"
    assert seen["start"].isoformat() == "2026-09-20T00:00:00+00:00" and seen["end"].day == 23


@pytest.mark.parametrize(
    "args",
    [
        ["--domain", "example.edu", "--since", "2026-09-23", "--until", "2026-09-20"],
        ["--domain", "nope.example", "--since", "2026-09-20", "--until", "2026-09-23"],
        ["--domain", "example.edu", "--since", "bad", "--until", "2026-09-23"],
    ],
)
def test_dmarc_reports_cli_config_errors_exit_2(monkeypatch, capsys, args):
    import gwsadm_mcp.config as config
    from gwsadm_mcp import __main__ as cli
    from gwsadm_mcp.config import DomainConfig

    cfg = DomainConfig("example.edu", "/tmp/sa.json", "a@example.edu", "C0abc", "postmaster@example.edu")
    monkeypatch.setattr(config, "load_config", lambda: ([cfg], set()))
    monkeypatch.setattr("sys.argv", ["gwsadm-mcp", "dmarc-reports", *args])
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 2
    assert capsys.readouterr().out == ""


def test_dmarc_reports_cli_auth_failure_exit_1(monkeypatch, capsys):
    import gwsadm_mcp.client as client
    import gwsadm_mcp.config as config
    from gwsadm_mcp import __main__ as cli
    from gwsadm_mcp.config import DomainConfig

    cfg = DomainConfig("example.edu", "/tmp/sa.json", "a@example.edu", "C0abc", "postmaster@example.edu")
    monkeypatch.setattr(config, "load_config", lambda: ([cfg], set()))

    def boom(self, **kw):
        raise client.GwsAuthError("gmail.readonly not granted")

    monkeypatch.setattr(client.DomainClient, "fetch_dmarc_reports", boom)
    monkeypatch.setattr(
        "sys.argv",
        ["gwsadm-mcp", "dmarc-reports", "--domain", "example.edu", "--since", "2026-09-20", "--until", "2026-09-23"],
    )
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 1
    out = capsys.readouterr()
    assert out.out == "" and "gmail.readonly" in out.err
