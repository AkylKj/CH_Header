import pytest
import requests
from unittest.mock import MagicMock
from src.header_checker import check_security_headers, get_headers
from src.response_analyzer import ResponseAnalyzer


def test_real_headers_and_partial_cookie(http_server):
    result = check_security_headers(http_server + '/ok')
    assert result['success']
    assert result['headers']['Content-Security-Policy']['status'] == 'GOOD'
    assert result['headers']['Set-Cookie']['status'] == 'WARNING'
    assert result['summary']['warning'] == 1


@pytest.mark.parametrize('response', [False, True])
def test_redirects_and_limits(http_server, response):
    if response:
        fetch = ResponseAnalyzer().analyze_response_headers
        followed = fetch(http_server + '/redirect', max_redirects=1)
        assert followed['status_code'] == 200
        assert len(followed['redirect_chain']) == 1
        assert fetch(http_server + '/redirect', follow_redirects=False)['status_code'] == 302
    else:
        fetch = check_security_headers
        assert fetch(http_server + '/redirect', max_redirects=1)['success']
        assert 'Content-Security-Policy' in get_headers(http_server + '/redirect', follow_redirects=True)
        assert 'Location' in get_headers(http_server + '/redirect', follow_redirects=False)
    failed = fetch(http_server + '/loop', max_redirects=1)
    assert not failed['success']
    assert 'TooManyRedirects' in failed['error']


@pytest.mark.parametrize('fetch', [check_security_headers, ResponseAnalyzer().analyze_response_headers])
def test_timeout_details(http_server, fetch):
    result = fetch(http_server + '/slow', timeout=0.03)
    assert not result['success']
    assert 'Timeout' in result['error']


@pytest.mark.parametrize('response', [False, True])
def test_connection_cleanup(monkeypatch, response):
    session = MagicMock()
    session.__enter__.return_value = session
    reply = MagicMock()
    reply.__enter__.return_value = reply
    reply.headers = requests.structures.CaseInsensitiveDict({'content-security-policy': "default-src 'self'"})
    reply.history = []
    reply.status_code = 200
    session.get.return_value = reply
    monkeypatch.setattr(requests, 'Session', lambda: session)
    fetch = ResponseAnalyzer().analyze_response_headers if response else get_headers
    fetch('https://example.invalid', max_redirects=2)
    assert session.max_redirects == 2
    assert session.get.call_args.kwargs['stream'] is True
    assert 'max_redirects' not in session.get.call_args.kwargs
    reply.__exit__.assert_called_once()
    session.__exit__.assert_called_once()
