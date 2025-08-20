"""
Module for bulk checking multiple websites
"""

import asyncio
import aiohttp
import concurrent.futures
from typing import List, Dict, Optional
from pathlib import Path
import csv
import json
from datetime import datetime

from .header_checker import check_security_headers
from .ssl_checker import analyze_ssl_security

class BulkChecker:
    def __init__(self, parallel_workers: int = 1, batch_size: int = 10):
        self.parallel_workers = parallel_workers
        self.batch_size = batch_size
        self.results = []
        
    def load_urls_from_file(self, file_path: str) -> List[str]:
        """Loads URLs from file"""
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        if not url.startswith(('http://', 'https://')):
                            url = 'https://' + url
                        urls.append(url)
        except FileNotFoundError:
            raise FileNotFoundError(f"File {file_path} not found")
        return urls
    
    def parse_urls_string(self, urls_string: str) -> List[str]:
        """Parses comma-separated string of URLs"""
        urls = []
        for url in urls_string.split(','):
            url = url.strip()
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                urls.append(url)
        return urls
    
    def check_single_site(self, url: str, check_ssl: bool = False, timeout: int = 10, 
                         user_agent: str = None, follow_redirects: bool = True, 
                         max_redirects: int = 5, verify_ssl: bool = True) -> Dict:
        """Checks a single site"""
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'headers': None,
            'ssl': None,
            'error': None
        }
        
        try:
            # Check headers
            headers_result = check_security_headers(
                url, 
                timeout=timeout,
                user_agent=user_agent,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                verify_ssl=verify_ssl
            )
            if headers_result['success']:
                result['headers'] = headers_result
                result['success'] = True
            
            # Check SSL if needed
            if check_ssl:
                ssl_result = analyze_ssl_security(url, timeout)
                result['ssl'] = ssl_result
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def check_multiple_sites(self, urls: List[str], check_ssl: bool = False, 
                           timeout: int = 10, user_agent: str = None,
                           follow_redirects: bool = True, max_redirects: int = 5,
                           verify_ssl: bool = True) -> List[Dict]:
        """Checks multiple sites with parallel processing"""
        results = []
        
        if self.parallel_workers == 1:
            # Sequential processing
            for url in urls:
                result = self.check_single_site(
                    url, check_ssl, timeout, user_agent, 
                    follow_redirects, max_redirects, verify_ssl
                )
                results.append(result)
        else:
            # Parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                future_to_url = {
                    executor.submit(
                        self.check_single_site, url, check_ssl, timeout, user_agent,
                        follow_redirects, max_redirects, verify_ssl
                    ): url 
                    for url in urls
                }
                
                for future in concurrent.futures.as_completed(future_to_url):
                    result = future.result()
                    results.append(result)
        
        return results
    
    def generate_summary_report(self, results: List[Dict]) -> Dict:
        """Generates summary report"""
        total_sites = len(results)
        successful_checks = len([r for r in results if r['success']])
        failed_checks = total_sites - successful_checks
        
        # Header statistics
        header_scores = []
        ssl_scores = []
        
        for result in results:
            if result['success'] and result['headers']:
                header_scores.append(result['headers']['total_score'])
            
            if result['ssl']:
                ssl_scores.append(result['ssl']['score']['total_score'])
        
        summary = {
            'total_sites': total_sites,
            'successful_checks': successful_checks,
            'failed_checks': failed_checks,
            'success_rate': (successful_checks / total_sites * 100) if total_sites > 0 else 0,
            'average_header_score': sum(header_scores) / len(header_scores) if header_scores else 0,
            'average_ssl_score': sum(ssl_scores) / len(ssl_scores) if ssl_scores else 0,
            'best_sites': [],
            'worst_sites': []
        }
        
        # Top sites
        if header_scores:
            sorted_results = sorted(results, key=lambda x: x.get('headers', {}).get('total_score', 0), reverse=True)
            summary['best_sites'] = [r['url'] for r in sorted_results[:5]]
            summary['worst_sites'] = [r['url'] for r in sorted_results[-5:]]
        
        return summary
