import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import re

class ResponseAnalyzer:
    def __init__(self):
        self.status_codes = {
            200: "OK - Request succeeded",
            201: "Created - Resource created successfully",
            301: "Moved Permanently - Permanent redirect",
            302: "Found - Temporary redirect",
            304: "Not Modified - Resource not changed",
            307: "Temporary Redirect - Temporary redirect",
            308: "Permanent Redirect - Permanent redirect",
            400: "Bad Request - Invalid request",
            401: "Unauthorized - Authentication required",
            403: "Forbidden - Access denied",
            404: "Not Found - Resource not found",
            405: "Method Not Allowed - HTTP method not supported",
            429: "Too Many Requests - Rate limited",
            500: "Internal Server Error - Server error",
            502: "Bad Gateway - Gateway error",
            503: "Service Unavailable - Service temporarily unavailable",
            504: "Gateway Timeout - Gateway timeout"
        }
        
        self.server_info = {
            'apache': 'Apache HTTP Server',
            'nginx': 'Nginx',
            'iis': 'Microsoft IIS',
            'cloudflare': 'Cloudflare',
            'cloudfront': 'Amazon CloudFront',
            'fastly': 'Fastly CDN',
            'akamai': 'Akamai CDN',
            'gws': 'Google Web Server',
            'gse': 'Google Server'
        }
    
    def analyze_response_headers(self, url: str, timeout: int = 10, 
                               user_agent: str = None, follow_redirects: bool = True,
                               max_redirects: int = 5, verify_ssl: bool = True) -> Dict:
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status_code': None,
            'status_message': None,
            'response_time': None,
            'server_info': {},
            'security_headers': {},
            'additional_headers': {},
            'redirect_chain': [],
            'error': None
        }
        
        try:
            # Prepare request headers
            headers = {}
            if user_agent:
                headers['User-Agent'] = user_agent
            
            # Make request
            start_time = datetime.now()
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=verify_ssl,
                stream=True  # Don't download content
            )
            end_time = datetime.now()
            
            # Calculate response time
            result['response_time'] = (end_time - start_time).total_seconds()
            result['status_code'] = response.status_code
            result['status_message'] = self.status_codes.get(response.status_code, "Unknown status code")
            result['success'] = True
            
            # Analyze headers
            self._analyze_headers(response.headers, result)
            
            # Analyze redirect chain
            if follow_redirects and response.history:
                result['redirect_chain'] = [
                    {
                        'url': resp.url,
                        'status_code': resp.status_code,
                        'status_message': self.status_codes.get(resp.status_code, "Unknown")
                    }
                    for resp in response.history
                ]
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_headers(self, headers: Dict, result: Dict):
        # Server information
        if 'Server' in headers:
            server_header = headers['Server'].lower()
            result['server_info']['server'] = headers['Server']
            
            # Detect server type
            for key, name in self.server_info.items():
                if key in server_header:
                    result['server_info']['detected_type'] = name
                    break
        
        # Security headers (already covered in header_checker, but additional analysis)
        security_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
            'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy',
            'Permissions-Policy', 'Cache-Control', 'Set-Cookie', 'Clear-Site-Data',
            'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy'
        ]
        
        for header in security_headers:
            if header in headers:
                result['security_headers'][header] = {
                    'value': headers[header],
                    'present': True
                }
            else:
                result['security_headers'][header] = {
                    'value': None,
                    'present': False
                }
        
        # Additional interesting headers
        additional_headers = [
            'Content-Type', 'Content-Length', 'Last-Modified', 'ETag',
            'Accept-Ranges', 'Connection', 'Keep-Alive', 'Date',
            'Vary', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers', 'Access-Control-Max-Age'
        ]
        
        for header in additional_headers:
            if header in headers:
                result['additional_headers'][header] = headers[header]
    
    def analyze_status_code(self, status_code: int) -> Dict:
        """Analyzes HTTP status code"""
        category = self._get_status_category(status_code)
        
        return {
            'code': status_code,
            'message': self.status_codes.get(status_code, "Unknown status code"),
            'category': category,
            'is_success': 200 <= status_code < 300,
            'is_redirect': 300 <= status_code < 400,
            'is_client_error': 400 <= status_code < 500,
            'is_server_error': 500 <= status_code < 600
        }
    
    def _get_status_category(self, status_code: int) -> str:
        """Gets status code category"""
        if 100 <= status_code < 200:
            return "Informational"
        elif 200 <= status_code < 300:
            return "Success"
        elif 300 <= status_code < 400:
            return "Redirection"
        elif 400 <= status_code < 500:
            return "Client Error"
        elif 500 <= status_code < 600:
            return "Server Error"
        else:
            return "Unknown"
    
    def detect_server_technology(self, headers: Dict) -> Dict:
        detection = {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', None),
            'detected_technologies': []
        }
        
        # Analyze Server header
        server_lower = detection['server'].lower()
        for key, name in self.server_info.items():
            if key in server_lower:
                detection['detected_technologies'].append(name)
        
        # Analyze X-Powered-By header
        if detection['powered_by']:
            powered_by_lower = detection['powered_by'].lower()
            if 'php' in powered_by_lower:
                detection['detected_technologies'].append('PHP')
            if 'asp.net' in powered_by_lower:
                detection['detected_technologies'].append('ASP.NET')
            if 'express' in powered_by_lower:
                detection['detected_technologies'].append('Express.js')
            if 'django' in powered_by_lower:
                detection['detected_technologies'].append('Django')
        
        return detection