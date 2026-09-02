"""Tests for config parsing and internal/external classification."""

import pytest

from gwsadm_mcp.config import ConfigError, is_external, load_config

GOOD = """
[gwsadm]
internal_domains = example.edu, mail.example.edu

[domain.example.edu]
service_account_file = /tmp/sa.json
subject = audit-admin@example.edu
customer_id = C0abc

[domain.students.example.edu]
service_account_file = /tmp/sa2.json
subject = audit-admin@students.example.edu
customer_id = C0def
"""


def test_load_config_parses_domains_and_allowlist(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(GOOD)
    domains, internal = load_config(str(p))
    assert [d.domain for d in domains] == ["example.edu", "students.example.edu"]
    assert domains[0].customer_id == "C0abc"
    assert internal == {"example.edu", "mail.example.edu"}


def test_internal_domains_default_to_section_names(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(GOOD.replace("internal_domains = example.edu, mail.example.edu", ""))
    _, internal = load_config(str(p))
    assert internal == {"example.edu", "students.example.edu"}


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "absent.ini"))


def test_missing_key_raises(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text("[domain.example.edu]\nservice_account_file = /tmp/sa.json\nsubject = a@example.edu\n")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_no_domain_sections_raises(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text("[gwsadm]\ninternal_domains = example.edu\n")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_duplicate_domain_differing_only_in_case_raises(tmp_path):
    # configparser section names are case-sensitive, so both sections parse
    # and would silently yield two clients for the same lowercased domain
    # (e.g. a stale section left behind during a key rotation).
    p = tmp_path / "config.ini"
    p.write_text(
        GOOD
        + "\n[domain.Example.edu]\n"
        + "service_account_file = /tmp/sa-old.json\n"
        + "subject = audit-admin@example.edu\n"
        + "customer_id = C0abc\n"
    )
    with pytest.raises(ConfigError, match="duplicate domain 'example.edu'"):
        load_config(str(p))


def test_is_external():
    internal = {"example.edu"}
    assert not is_external("user@example.edu", internal)
    assert not is_external("user@EXAMPLE.EDU", internal)
    assert is_external("user@gmail.com", internal)
    assert is_external(None, internal)  # anonymous must count as external
    assert is_external("not-an-address", internal)


def test_dmarc_rua_defaults_to_postmaster_for_both_mailbox_and_recipient(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(GOOD)
    domains, _ = load_config(str(p))
    assert domains[0].dmarc_rua_mailbox == "postmaster@example.edu"
    assert domains[0].dmarc_rua_recipient == "postmaster@example.edu"


def test_dmarc_rua_recipient_defaults_to_explicit_mailbox(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(GOOD.replace("customer_id = C0abc", "customer_id = C0abc\ndmarc_rua_mailbox = dmarc-bot@example.edu"))
    domains, _ = load_config(str(p))
    assert domains[0].dmarc_rua_mailbox == "dmarc-bot@example.edu"
    assert domains[0].dmarc_rua_recipient == "dmarc-bot@example.edu"


def test_dmarc_rua_recipient_parsed_separately_from_mailbox(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(
        GOOD.replace(
            "customer_id = C0abc",
            "customer_id = C0abc\ndmarc_rua_mailbox = dmarc-bot@example.edu\n"
            "dmarc_rua_recipient = postmaster+rua@example.edu",
        )
    )
    domains, _ = load_config(str(p))
    assert domains[0].dmarc_rua_mailbox == "dmarc-bot@example.edu"
    assert domains[0].dmarc_rua_recipient == "postmaster+rua@example.edu"


def test_dmarc_rua_mailbox_none_opts_out_case_insensitively(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(GOOD.replace("customer_id = C0def", "customer_id = C0def\ndmarc_rua_mailbox = NONE"))
    domains, _ = load_config(str(p))
    assert domains[1].dmarc_rua_mailbox is None
    assert domains[1].dmarc_rua_recipient is None
    assert domains[0].dmarc_rua_mailbox == "postmaster@example.edu"  # other sections unaffected


def test_dmarc_rua_recipient_without_mailbox_is_a_config_error(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(
        GOOD.replace(
            "customer_id = C0def",
            "customer_id = C0def\ndmarc_rua_mailbox = none\ndmarc_rua_recipient = postmaster+rua@example.edu",
        )
    )
    with pytest.raises(ConfigError, match="dmarc_rua_recipient"):
        load_config(str(p))


def test_inline_comments_are_stripped_from_values(tmp_path):
    """Every documented example annotates its keys with a trailing comment.

    Copying one verbatim must not put the comment INSIDE the value: the failures
    are silent, not loud -- a commented ``dmarc_rua_mailbox = none`` stops matching
    the opt-out sentinel and becomes a literal mailbox, and a commented recipient
    smuggles extra terms into the Gmail search behind ``to:``.
    """
    p = tmp_path / "config.ini"
    p.write_text(
        "[domain.example.edu]\n"
        "service_account_file = /tmp/sa.json   # the key downloaded from GCP\n"
        "subject = audit-admin@example.edu     ; an admin who can be impersonated\n"
        "customer_id = C0abc\n"
        'dmarc_rua_mailbox = none   # optional, default: postmaster@<domain>; "none" opts out\n'
    )
    domains, _ = load_config(str(p))
    d = domains[0]
    assert d.service_account_file == "/tmp/sa.json"
    assert d.subject == "audit-admin@example.edu"
    assert d.dmarc_rua_mailbox is None  # the sentinel still opts the domain out
    assert d.dmarc_rua_recipient is None


def test_inline_comment_stripping_keeps_recipient_usable_in_a_search(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text(
        "[domain.example.edu]\n"
        "service_account_file = /tmp/sa.json\n"
        "subject = audit-admin@example.edu\n"
        "customer_id = C0abc\n"
        "dmarc_rua_mailbox = dmarc-bot@example.edu       # the real user to impersonate\n"
        "dmarc_rua_recipient = postmaster+rua@example.edu ; the published rua= address\n"
    )
    domains, _ = load_config(str(p))
    d = domains[0]
    assert d.dmarc_rua_mailbox == "dmarc-bot@example.edu"
    assert d.dmarc_rua_recipient == "postmaster+rua@example.edu"
    # nothing that would change the meaning of ``to:{recipient} after:...``
    assert not any(ch.isspace() for ch in d.dmarc_rua_recipient)


def test_a_value_containing_a_hash_mid_token_is_not_truncated(tmp_path):
    """configparser only treats #/; as a comment when whitespace precedes it."""
    p = tmp_path / "config.ini"
    p.write_text(
        "[domain.example.edu]\n"
        "service_account_file = /tmp/sa#1.json\n"
        "subject = audit-admin@example.edu\n"
        "customer_id = C0abc\n"
    )
    domains, _ = load_config(str(p))
    assert domains[0].service_account_file == "/tmp/sa#1.json"
