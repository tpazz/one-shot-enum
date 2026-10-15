import importlib.util
import json
from pathlib import Path
import sys


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
