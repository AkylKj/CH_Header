"""Bounded bulk execution with independent module results."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlsplit

from .header_checker import check_security_headers
from .http_client import fetch_response
from .ssl_checker import analyze_ssl_security
from .response_analyzer import ResponseAnalyzer


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'Invalid HTTP(S) URL: {url}')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError(f'Invalid port: {url}')
    return url


class BulkChecker:
    def __init__(self, parallel_workers: int = 1, batch_size: int = 10):
        if parallel_workers <= 0 or batch_size <= 0:
            raise ValueError('parallel_workers and batch_size must be positive')
        self.parallel_workers = parallel_workers
        self.batch_size = batch_size

    def load_urls_from_file(self, file_path: str) -> List[str]:
        with open(file_path, encoding='utf-8') as source:
            return self._normalize_urls(line.strip() for line in source
                                        if line.strip() and not line.lstrip().startswith('#'))

    def parse_urls_string(self, urls_string: str) -> List[str]:
        return self._normalize_urls(url.strip() for url in urls_string.split(',') if url.strip())

    @staticmethod
    def _normalize_urls(urls):
        return [validate_url(url if '://' in url else 'https://' + url) for url in urls]

    def check_single_site(self, url: str, check_ssl: bool = False, timeout: int = 10,
                          user_agent: str = None, follow_redirects: bool = True,
                          max_redirects: int = 5, verify_ssl: bool = True,
                          check_headers: bool = True, check_response: bool = False) -> Dict:
        result = {'url': url, 'timestamp': datetime.now().isoformat(),
                  'success': False, 'headers': None, 'ssl': None,
                  'response': None, 'error': None, 'errors': {}}
        options = dict(timeout=timeout, user_agent=user_agent,
                       follow_redirects=follow_redirects,
                       max_redirects=max_redirects, verify_ssl=verify_ssl)
        snapshot, http_error = None, None
        if check_headers or check_response:
            try:
                snapshot = fetch_response(url, **options)
            except Exception as exc:
                http_error = f'{type(exc).__name__}: {exc}'
        checks = []
        if check_headers:
            checks.append(('headers', lambda: check_security_headers(url, **options, snapshot=snapshot, http_error=http_error)))
        if check_ssl:
            checks.append(('ssl', lambda: analyze_ssl_security(url, timeout)))
        if check_response:
            checks.append(('response', lambda: ResponseAnalyzer().analyze_response_headers(url, **options, snapshot=snapshot, http_error=http_error)))
        for module, run in checks:
            try:
                value = run()
            except Exception as exc:
                value = {'success': False, 'error': f'{type(exc).__name__}: {exc}'}
            result[module] = value
            if not value.get('success'):
                result['errors'][module] = value.get('error') or 'Analysis incomplete'
        result['success'] = bool(checks) and not result['errors']
        result['error'] = '; '.join(f'{module}: {error}' for module, error in result['errors'].items()) or None
        return result

    def check_multiple_sites(self, urls: List[str], check_ssl: bool = False,
                             timeout: int = 10, user_agent: str = None,
                             follow_redirects: bool = True, max_redirects: int = 5,
                             verify_ssl: bool = True, check_headers: bool = True,
                             check_response: bool = False) -> List[Dict]:
        options = dict(check_ssl=check_ssl, timeout=timeout, user_agent=user_agent,
                       follow_redirects=follow_redirects, max_redirects=max_redirects,
                       verify_ssl=verify_ssl, check_headers=check_headers,
                       check_response=check_response)
        results = []
        with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
            for start in range(0, len(urls), self.batch_size):
                batch = urls[start:start + self.batch_size]
                futures = [executor.submit(self.check_single_site, url, **options) for url in batch]
                # Finish this bounded batch before submitting the next one.
                results.extend(future.result() for future in futures)
        return results

    def generate_summary_report(self, results: List[Dict]) -> Dict:
        total = len(results)
        successful = sum(bool(result['success']) for result in results)
        scored = [r for r in results if (r.get('headers') or {}).get('success')
                  and r['headers'].get('max_score', 0) > 0]
        header_scores = [r['headers']['total_score'] for r in scored]
        header_percentages = [r['headers']['total_score'] / r['headers']['max_score'] * 100
                              for r in scored]
        ssl_scores = [r['ssl']['score']['total_score'] for r in results
                      if (r.get('ssl') or {}).get('success')]
        ranked = sorted(scored, key=lambda r: r['headers']['total_score'] / r['headers']['max_score'], reverse=True)
        worst_ranked = sorted(scored, key=lambda r: r['headers']['total_score'] / r['headers']['max_score'])
        return {
            'total_sites': total, 'successful_checks': successful,
            'failed_checks': total - successful,
            'success_rate': successful / total * 100 if total else 0,
            'average_header_score': sum(header_scores) / len(header_scores) if header_scores else None,
            'average_header_percentage': (sum(header_percentages) / len(header_percentages)
                                          if header_percentages else None),
            'average_ssl_score': sum(ssl_scores) / len(ssl_scores) if ssl_scores else 0,
            'best_sites': [r['url'] for r in ranked[:5]],
            'worst_sites': [r['url'] for r in worst_ranked[:5]]
        }
