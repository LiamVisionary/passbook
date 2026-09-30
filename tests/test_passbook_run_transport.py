"""Run diagnostics cannot turn a refused broker socket into a locked vault."""
import passbook_broker as broker
from test_passbook_run_only import _in_process_run


def unavailable(monkeypatch):
    monkeypatch.setattr(broker, "vault_status", lambda: {
        "ok": False, "status": "unavailable", "unlocked": None,
        "error": "This process cannot access PassBook.",
    })


def test_all_unresolved_keys_report_transport_not_lock(monkeypatch, capsys):
    unavailable(monkeypatch)
    err, handed = _in_process_run(monkeypatch, capsys, resolved={}, stored=["ALPHA", "BETA"], only=["ALPHA"])
    assert "cannot access PassBook" in err
    assert "locked" not in err.lower()
    assert "passbook signin" not in err
    assert "ALPHA" not in handed and "BETA" not in handed


def test_partial_store_reports_transport_and_preserves_readable_values(monkeypatch, capsys):
    unavailable(monkeypatch)
    err, handed = _in_process_run(monkeypatch, capsys, resolved={"BETA": "fixture-readable"}, stored=["ALPHA", "BETA"], only=["ALPHA", "BETA"])
    assert "cannot access PassBook" in err
    assert "passbook signin" not in err
    assert "ALPHA" in err
    assert "ALPHA" not in handed and handed["BETA"] == "fixture-readable"


def test_transport_unknown_never_claims_nothing_is_locked(monkeypatch, capsys):
    unavailable(monkeypatch)
    err, _ = _in_process_run(monkeypatch, capsys, resolved={"BETA": "fixture-readable"}, stored=["ALPHA", "BETA"], only=["ALPHA", "TYPO"])
    assert "Not in the store: TYPO" in err
    assert "cannot access PassBook" in err
    assert "locked" not in err.lower()
    assert "passbook signin" not in err


def test_resolved_requested_key_needs_no_new_broker_probe(monkeypatch, capsys):
    monkeypatch.setattr(broker, "vault_status", lambda: (_ for _ in ()).throw(AssertionError("Resolved keys need no status read")))
    err, handed = _in_process_run(monkeypatch, capsys, resolved={"BETA": "fixture-readable"}, stored=["ALPHA", "BETA"], only=["BETA"])
    assert not err
    assert handed["BETA"] == "fixture-readable"
