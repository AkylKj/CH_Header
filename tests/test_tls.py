import socket
import ssl
import pytest
from unittest.mock import MagicMock
from src import ssl_checker as tls


@pytest.mark.parametrize('kind', ['valid', 'untrusted', 'expired', 'mismatch'])
def test_real_certificate_validation(tls_server, monkeypatch, kind):
    url, ca = tls_server(expired=kind == 'expired', mismatch=kind == 'mismatch')
    original = ssl.create_default_context
    if kind != 'untrusted':
        monkeypatch.setattr(tls.ssl, 'create_default_context', lambda: original(cafile=ca))
    result = tls.check_ssl_certificate(url)
    assert result['parsed']
    assert result['success'] == (kind == 'valid')
    assert result['verified'] == (kind == 'valid')
    assert result['is_expired'] == (kind == 'expired')
    assert result['hostname_valid'] == (kind != 'mismatch')
    assert result['signature_algorithm'] == 'sha256'
    if kind != 'valid':
        assert result['verification_error']
        assert result['verification_code'] is not None


@pytest.mark.parametrize('url,host,port', [
    ('https://[::1]:8443/a?q=x', '::1', 8443),
    ('https://example.com?a=1', 'example.com', 443),
    ('http://example.com/path', 'example.com', 443)])
def test_url_parsing(url, host, port):
    assert tls.get_hostname_and_port(url) == (host, port)


@pytest.mark.parametrize('url', ['https://', 'ftp://example.com', 'https://example.com:bad'])
def test_bad_tls_url(url):
    assert not tls.check_ssl_certificate(url)['success']
    assert not tls.check_tls_protocols(url)['success']
    assert not tls.check_cipher_suites(url)['success']


@pytest.mark.parametrize('reason,expected', [('NO_CIPHERS_AVAILABLE', None),
    ('UNSUPPORTED_PROTOCOL', None), ('SSLV3_ALERT_HANDSHAKE_FAILURE', None),
    ('TLSV1_ALERT_PROTOCOL_VERSION', False)])
def test_protocol_error_classification(monkeypatch, reason, expected):
    exc = ssl.SSLError(1, reason)
    exc.reason = reason
    context = MagicMock()
    context.wrap_socket.side_effect = exc
    monkeypatch.setattr(tls.ssl, 'SSLContext', lambda *args: context)
    monkeypatch.setattr(tls.socket, 'create_connection', lambda *args, **kwargs: MagicMock())
    result = tls.check_tls_protocols('https://example.invalid')
    assert all(info['supported'] is expected for info in result['protocols'].values())
    assert result['complete'] == (expected is not None)


def test_network_failure_unknown(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.timeout('unreachable')
    monkeypatch.setattr(tls.socket, 'create_connection', fail)
    result = tls.check_tls_protocols('https://example.invalid')
    assert not result['success']
    assert all(info['status'] == 'UNKNOWN' for info in result['protocols'].values())


def test_negotiated_cipher_local(tls_server):
    url, _ = tls_server()
    result = tls.check_cipher_suites(url)
    assert result['success']
    assert result['scope'] == 'negotiated_suite_only'
    assert result['strong_ciphers']


def test_score_maximum_and_untrusted():
    cert = {'success': True, 'parsed': True, 'verified': True, 'hostname_valid': True,
            'is_expired': False, 'signature_algorithm': 'sha256'}
    protocols = {'success': True, 'complete': True, 'protocols': {
        'TLS 1.3': {'supported': True}, 'TLS 1.2': {'supported': True},
        'TLS 1.1': {'supported': False}, 'TLS 1.0': {'supported': False}}}
    ciphers = {'success': True, 'strong_ciphers': ['TLS_AES_256_GCM_SHA384']}
    result = tls.calculate_ssl_score(cert, protocols, ciphers)
    assert result['total_score'] == result['max_score'] == 95
    assert result['percentage'] == 100
    cert.update(success=False, verified=False)
    assert tls.calculate_ssl_score(cert, protocols, ciphers)['total_score'] == 70
    protocols['complete'] = False
    protocols['protocols']['TLS 1.0']['supported'] = None
    result = tls.calculate_ssl_score(cert, protocols, ciphers)
    assert result['security_level'] == 'Incomplete'
    assert 'UNKNOWN: TLS 1.0 could not be checked' in result['details']


@pytest.mark.parametrize('pattern,host,match', [('*.example.com','www.example.com',True),
    ('*.example.com','example.com',False),('*.example.com','a.b.example.com',False)])
def test_fallback_wildcard(pattern, host, match):
    assert tls._dns_matches(pattern, host) is match
