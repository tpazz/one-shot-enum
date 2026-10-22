import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('gate_enum',Path(__file__).parents[1]/'one-shot-enum.py')
enum=importlib.util.module_from_spec(spec)
spec.loader.exec_module(enum)


def response(text, media='text/html', payload=None):
    return {'status':200,'content_type':media,'text':text,'json':payload}


def test_same_gate_with_rotating_nonce_has_the_same_body_fingerprint():
    template='<html><title>Private portal</title><script nonce="{}">window.ready=true</script><style nonce="{}">body{{color:white}}</style><p>Sign in</p></html>'
    assert enum._response_fingerprint(response(template.format('nonce-one','nonce-a'))) == enum._response_fingerprint(response(template.format('nonce-two','nonce-b')))


def test_equal_title_status_and_size_do_not_collapse_different_content():
    first='<title>Service</title><script nonce="a">const mode="admin"</script>'
    other='<title>Service</title><script nonce="b">const mode="guest"</script>'
    assert len(first)==len(other)
    assert enum._response_fingerprint(response(first)) != enum._response_fingerprint(response(other))


def test_actual_api_nonce_values_and_non_csp_attributes_are_preserved():
    assert enum._response_fingerprint(response('', 'application/json', {'nonce':'one'})) != enum._response_fingerprint(response('', 'application/json', {'nonce':'two'}))
    assert enum._response_fingerprint(response('<div nonce="one">Data</div>')) != enum._response_fingerprint(response('<div nonce="two">Data</div>'))
    assert enum._response_fingerprint(response('<script src="one" nonce="a"></script>')) != enum._response_fingerprint(response('<script src="two" nonce="b"></script>'))


def test_whitespace_inside_script_values_remains_significant():
    first = '<script nonce="a">const value="a  b"</script>'
    other = '<script nonce="b">const value="a b"</script>'
    assert enum._response_fingerprint(response(first)) != enum._response_fingerprint(response(other))
