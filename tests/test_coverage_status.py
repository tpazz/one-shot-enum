import importlib.util
import json
from pathlib import Path
import sys
import pytest


def test_mixed_discovery_preserves_loot_and_reports_partial_coverage(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('enum_coverage', Path(__file__).parents[1]/'one-shot-enum.py')
    enum = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = enum
    spec.loader.exec_module(enum)
    monkeypatch.setattr(sys, 'argv', ['enum', '192.0.2.1', '192.0.2.2', '--save', '--outdir', str(tmp_path)])
    monkeypatch.setattr(enum, 'nmap_installed', lambda: True)
    def discover(target, *args, **kwargs):
        if target == '192.0.2.1':
            raise RuntimeError('discovery timed out')
        return {'target': target, 'ip': target, 'hostname': '', 'extra': {}, 'open_ports': []}
    monkeypatch.setattr(enum, 'tcp_discovery_scan', discover)
    assert enum.main() == 2
    status = json.loads((tmp_path/'enum-status.json').read_text())
    assert status['execution_status'] == 'partial'
    assert status['errors'] == ['192.0.2.1: discovery timed out']
    assert status['targets'][1]['status'] == 'completed'
    assert (tmp_path/'services_summary.csv').is_file()


@pytest.mark.parametrize('service_error,recon,expected', [
    (True, {'ran': 66, 'nonzero': 19, 'failed': 0, 'timed_out': 6, 'interrupted': 0}, 'partial'),
    (False, {'ran': 66, 'nonzero': 19, 'failed': 0, 'timed_out': 6, 'interrupted': 0}, 'partial'),
    (False, {'ran': 1, 'interrupted': 1}, 'partial'),
    (False, {'ran': 2, 'nonzero': 0, 'timed_out': 0}, 'completed'),
])
def test_recon_coverage_is_finalized_after_tools_run(tmp_path, monkeypatch, service_error, recon, expected):
    spec = importlib.util.spec_from_file_location('enum_recon_coverage', Path(__file__).parents[1]/'one-shot-enum.py')
    enum = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = enum
    spec.loader.exec_module(enum)
    monkeypatch.setattr(sys, 'argv', ['enum', '192.0.2.1', '--save', '--outdir', str(tmp_path),
                                    '--recon-exec', '--loot-dir', str(tmp_path)])
    monkeypatch.setattr(enum, 'nmap_installed', lambda: True)
    monkeypatch.setattr(enum, 'tcp_discovery_scan', lambda *a, **kw: {
        'target': '192.0.2.1', 'ip': '192.0.2.1', 'hostname': '', 'extra': {}, 'open_ports': [80]})
    def service_scan(*args, **kwargs):
        if service_error:
            raise RuntimeError('service detection timed out')
        return {'services': []}
    monkeypatch.setattr(enum, 'tcp_service_scan', service_scan)
    monkeypatch.setattr(enum, '_probe_edge_headers', lambda *a, **kw: {})
    monkeypatch.setattr(enum, 'detect_cdn', lambda *a, **kw: None)
    monkeypatch.setattr(enum, 'write_llm_enum_loot', lambda *a, **kw: None)
    monkeypatch.setattr(enum, 'suggest_for_host', lambda *a, **kw: [{'tool': 'fixture'}])
    monkeypatch.setattr(enum, 'run_suggestions', lambda *a, **kw: recon)
    assert enum.main() == (2 if expected == 'partial' else None)
    status = json.loads((tmp_path/'enum-status.json').read_text())
    assert status['execution_status'] == expected
    assert status['recon'] == recon
    if service_error:
        assert status['targets'][0]['status'] == 'partial'
        assert any('service detection timed out' in error for error in status['errors'])
    if recon.get('timed_out'):
        assert any('19 non-zero exits' in error and '6 timed out' in error for error in status['errors'])
