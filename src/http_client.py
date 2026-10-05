"""Fetch and detach one HTTP response for all enabled HTTP analyzers."""
from time import perf_counter

import requests


class HeaderSnapshot(requests.structures.CaseInsensitiveDict):
    """Mapping-compatible response snapshot; no live socket or response is retained."""
    def __init__(self, response, response_time=None):
        super().__init__(response.headers)
        self.final_url = response.url
        self.status_code = response.status_code
        self.response_time = response_time
        self.redirect_chain = [{'url': item.url, 'status_code': item.status_code}
                               for item in response.history]
        self.values_by_name = {}
        raw_headers = response.raw.headers
        for name in raw_headers:
            self.values_by_name[name.lower()] = list(raw_headers.getlist(name))

    def get_values(self, name):
        return self.values_by_name.get(name.lower(), [])


def fetch_response(
    url: str, timeout: int = 10,
    user_agent: str = 'Security-Header-Checker/0.0.6',
    follow_redirects: bool = True, max_redirects: int = 5,
    verify_ssl: bool = True
) -> HeaderSnapshot:
    """One GET operation, including allowed redirects, without reading the final body."""
    with requests.Session() as session:
        session.max_redirects = max_redirects
        headers = {'User-Agent': user_agent} if user_agent else {}
        start = perf_counter()
        with session.get(url, timeout=timeout, headers=headers,
                         allow_redirects=follow_redirects, verify=verify_ssl,
                         stream=True) as response:
            elapsed = perf_counter() - start
            return HeaderSnapshot(response, elapsed)
