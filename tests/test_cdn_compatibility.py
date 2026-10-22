import importlib.util
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('enum_cdn_compatibility', Path(__file__).parents[1]/'one-shot-enum.py')
enum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enum)


def test_private_host_and_generic_proxy_headers_do_not_imply_cdn():
    assert enum.detect_cdn('10.10.10.10', [22, 80, 2052, 2053, 2082, 2083]) is None
    assert enum.detect_cdn_from_headers({'Via': '1.1 varnish'}) is None
    assert enum.detect_cdn('104.21.88.5', [80]) == 'Cloudflare'


def test_corroborated_services_and_nonweb_observations_survive(tmp_path):
    path = tmp_path/'nmap.xml'
    path.write_text('<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.9" method="probed"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4" method="probed"/></port><port protocol="tcp" portid="5060"><state state="open"/><service name="sip" method="table"/></port></ports></host></nmaprun>')
    enum._rewrite_cdn_service_xml(path)
    ports = {p.attrib['portid']: p.find('service').attrib for p in ET.parse(path).iter('port')}
    assert ports['22']['product'] == 'OpenSSH'
    assert ports['80']['version'] == '2.4'
    assert ports['5060']['name'] == 'unknown'
    assert ports['5060']['omega_original_name'] == 'sip'


def test_web_recon_uses_hostname_but_loot_identity_remains_ip():
    service = {'port':443,'protocol':'tcp','service':'https','product':'','version':'','tunnel':'ssl','scripts':''}
    rows = enum.suggest_for_host('104.21.88.5', [service], [], 'loot', 'words.txt', 'users.txt', request_host='app.example.test')
    web = [r for r in rows if r['tool'] in ('whatweb','nikto','ffuf')]
    assert web and all('https://app.example.test:443' in r['command'] for r in web)
    assert all('loot/104.21.88.5/' in r['output_file'] for r in web)


def test_override_and_http_host_are_explicit_cli_options():
    with patch.object(sys, 'argv', ['enum', '10.10.10.10', '--cdn-mode', 'off', '--http-host', 'app.box']):
        args = enum.parse_args()
    assert args.cdn_mode == 'off' and args.http_host == 'app.box'


def test_notebook_read_only_json_is_protocol_evidence():
    assert enum._probe_protocol_verified('/api/kernels', {'status':200,'json':[{'id':'fixture','name':'python3'}]})
    assert not enum._probe_protocol_verified('/api/kernels', {'status':403,'json':[]})


def test_original_xml_is_preserved_for_standalone_pathfinder_without_save(tmp_path):
    def nmap(command, *args, **kwargs):
        path = Path(command[command.index('-oX') + 1])
        path.write_text('<nmaprun><host><address addr="104.21.88.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="2053"><state state="open"/><service name="knetd" method="table"/></port></ports></host></nmaprun>')
        return 0, ''
    with patch.object(enum, 'run_nmap_with_progress', side_effect=nmap):
        result = enum.tcp_service_scan('104.21.88.5', [2053], None, loot_xml_dir=tmp_path/'loot', cdn='Cloudflare')
    raw = ET.parse(tmp_path/'loot/tcp_services.xml.raw')
    normalized = ET.parse(tmp_path/'loot/nmap.xml')
    assert raw.find('.//service').get('name') == 'knetd'
    assert normalized.find('.//service').get('name') == 'https'
    assert result['services'][0]['service'] == 'https'
