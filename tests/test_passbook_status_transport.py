"""A sandbox refusing the broker is not evidence that the vault is locked."""
import argparse
from contextlib import contextmanager
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import passbook
import passbook_broker as broker
import passbook_cli as cli


def test_vault_status_distinguishes_permission_denial(monkeypatch):
    @contextmanager
    def denied(*args, **kwargs):
        raise PermissionError('Operation not permitted')
        yield
    monkeypatch.setattr(broker, '_dial', denied)
    result = broker.vault_status(workspace='main')
    assert result.get('status') == 'unavailable'
    assert result['unlocked'] is None
    assert 'access' in result['error'].lower()


def test_vault_cli_does_not_report_unknown_state_as_locked(monkeypatch, capsys):
    import passbook_vault
    monkeypatch.setattr(passbook_vault, 'status', lambda: dict(supported=True, profiles=[], active='', sealed=1, legacy_v1=0, plaintext=0, fully_sealed=True, detail='Store encrypted.'))
    monkeypatch.setattr(broker, 'vault_status', lambda: dict(ok=False, status='unavailable', running=None, unlocked=None, error='This process cannot access PassBook.'))
    monkeypatch.setattr(cli, '_keystore_note', lambda: '')
    monkeypatch.setattr(cli, '_stay_open_state', lambda: {})
    code = cli.cmd_vault(argparse.Namespace(stay_open=None, json=False))
    captured = capsys.readouterr()
    assert 'locked' not in captured.out.lower()
    assert 'cannot access' in captured.out.lower()
    assert code == 1


def test_check_reports_access_issue_without_suggesting_signin(monkeypatch, capsys):
    monkeypatch.setattr(cli, '_use_broker_for_sealed_values', lambda *a, **k: None)
    monkeypatch.setattr(cli, '_store_values', lambda: {})
    monkeypatch.setattr(passbook, 'key_names', lambda: ['EXAMPLE_KEY'])
    monkeypatch.setattr(cli, '_refusals', lambda *a: {})
    monkeypatch.setattr(cli, '_sealed_refusal', lambda *a: '')
    monkeypatch.setattr(broker, 'vault_status', lambda: dict(ok=False, status='unavailable', unlocked=None, error='This process cannot access PassBook.'))
    code = cli.cmd_check(argparse.Namespace(keys=['EXAMPLE_KEY'], quiet=False, length=False, app=''))
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert 'locked' not in combined.lower()
    assert 'passbook signin' not in combined
    assert 'cannot access' in combined.lower()
    assert code == 1
