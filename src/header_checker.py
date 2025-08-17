"""
Module for checking the security of the site
"""

import requests
from typing import Dict, List, Optional
from colorama import Fore, Style
from typing import Tuple,List,Dict,Optional

SECURE_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Enforces the use of HTTPS',
        'good_values': ['max-age=31536000', 'max-age=63072000'],
        'score': 10
    },
    'Content-Security-Policy': {
        'description': 'Content security policy to prevent XSS and data injection attacks',
        'good_values': ['default-src', 'script-src', 'style-src'],
        'score': 15
    },
    'X-Frame-Options': {
        'description': 'Protection against clickjacking',
        'good_values': ['DENY', 'SAMEORIGIN'],
        'score': 8
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME-sniffing',
        'good_values': ['nosniff'],
        'score': 5
    },
    'X-XSS-Protection': {
        'description': 'Protection against XSS attacks',
        'good_values': ['1', '1; mode=block'],
        'score': 5
    },
    'Referrer-Policy': {
        'description': 'Controls the information sent in the Referer header',
        'good_values': ['strict-origin', 'strict-origin-when-cross-origin'],
        'score': 3
    },
    'Permissions-Policy': {
        'description': 'Controls access to browser features',
        'good_values': ['geolocation', 'camera', 'microphone'],
        'score': 4
    }
}

# Get headers from the site
def get_headers(
    url: str, 
    timeout: int = 10,
    user_agent: str = 'Security-Header-Checker/1.0',
    follow_redirects: bool = True,
    max_redirects: int = 5,
    verify_ssl: bool = True
) -> Dict[str, str]:
    """
    Gets HTTP headers from the site
    
    Args:
        url (str): URL of the site to check
        timeout (int): Request timeout in seconds
        user_agent (str): User-Agent string
        follow_redirects (bool): Follow redirects
        max_redirects (int): Maximum number of redirects
        verify_ssl (bool): Verify SSL certificates
        
    Returns:
        Dict[str, str]: Dictionary with headers
    """
    try:
        # Setup session
        session = requests.Session()
        
        # Setup headers
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Setup request parameters
        request_params = {
            'timeout': timeout,
            'headers': headers,
            'allow_redirects': follow_redirects,
            'verify': verify_ssl,
        }
        
        # Add max_redirects if follow_redirects=True
        if follow_redirects:
            request_params['max_redirects'] = max_redirects
        
        # Make GET request
        response = session.get(url, **request_params)
        
        return dict(response.headers)
        
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}Error: Request timeout after {timeout} seconds{Style.RESET_ALL}")
        return {}
    except requests.exceptions.SSLError:
        print(f"{Fore.RED}Error: SSL certificate verification failed{Style.RESET_ALL}")
        return {}
    except requests.exceptions.TooManyRedirects:
        print(f"{Fore.RED}Error: Too many redirects (max: {max_redirects}){Style.RESET_ALL}")
        return {}
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return {}

# Analyze headers from the site
def analyze_header(header_name: str, header_value: str) -> Tuple[int, str, str]:

    if header_name not in SECURE_HEADERS:
        return 0, "INFO", f"Unknown header: {header_name}"

    header_info = SECURE_HEADERS[header_name]
    value = header_value.lower()

    # Check if header value is in good_values
    for good_value in header_info['good_values']:
        if good_value.lower() in value:
            return header_info['score'], "GOOD", f"✅ {header_info['description']}"
        
    return 0, "BAD", f"❌ {header_info['description']}"
    

def check_security_headers(
    url: str,
    timeout: int = 10,
    user_agent: str = 'Security-Header-Checker/1.0',
    follow_redirects: bool = True,
    max_redirects: int = 5,
    verify_ssl: bool = True
) -> Dict:

    headers = get_headers(
        url, 
        timeout=timeout,
        user_agent=user_agent,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        verify_ssl=verify_ssl
    )

    if not headers:
        return {
            'success': False,
            'error': 'No headers found',
        }

    results = {
        'success': True,
        'url': url,
        'total_score': 0,
        'max_score': sum(header['score'] for header in SECURE_HEADERS.values()),
        'headers': {},
        'summary': {
            'good': 0,
            'bad': 0,
            'info': 0,
        }
    }

    for header_name in SECURE_HEADERS:
        if header_name in headers:
            score, status, description = analyze_header(header_name, headers[header_name])
            results['headers'][header_name] = {
                'value': headers[header_name],
                'score': score,
                'status': status,
                'description': description,
            }
            results['total_score'] += score
            results['summary'][status.lower()] += 1
        
        else:
            results['headers'][header_name] = {
                'value': 'Not found',
                'score': 0,
                'status': 'BAD',
                'description': f"❌ {SECURE_HEADERS[header_name]['description']} - not found",
            }
            results['summary']['bad'] += 1
    
    return results




