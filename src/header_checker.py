
import requests
from colorama import Fore, Style
from typing import Dict, Tuple
from .header_rules import (analyze_csp, analyze_hsts, analyze_cookies,
                           analyze_framing, analyze_legacy, LEGACY_HEADERS,
                           analyze_cors, analyze_cache_control, analyze_clear_site_data,
                           CORS_HEADERS, CONTEXTUAL_HEADERS)
from .http_client import HeaderSnapshot, fetch_response

SECURE_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Enforces the use of HTTPS',
        'good_values': ['max-age=31536000', 'max-age=63072000'],
        'score': 10,
        'type': 'presence'
    },
    'Content-Security-Policy': {
        'description': 'Content security policy to prevent XSS and data injection attacks',
        'good_values': ['default-src', 'script-src', 'style-src'],
        'score': 15,
        'type': 'presence'
    },
    'X-Frame-Options': {
        'description': 'Effective framing restriction via enforced CSP or XFO',
        'good_values': ['DENY', 'SAMEORIGIN'],
        'score': 8,
        'type': 'presence'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME-sniffing',
        'good_values': ['nosniff'],
        'score': 5,
        'type': 'presence'
    },
    'X-XSS-Protection': {
        'description': 'Deprecated browser XSS filtering (informational only)',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Referrer-Policy': {
        'description': 'Controls the information sent in the Referer header',
        'good_values': ['strict-origin', 'strict-origin-when-cross-origin'],
        'score': 3,
        'type': 'presence'
    },
    'Permissions-Policy': {
        'description': 'Controls access to browser features',
        'good_values': ['geolocation', 'camera', 'microphone'],
        'score': 4,
        'type': 'presence'
    },
    'Access-Control-Allow-Origin': {
        'description': 'CORS policy for cross-origin requests',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Access-Control-Allow-Methods': {
        'description': 'Allowed HTTP methods for CORS',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Access-Control-Allow-Headers': {
        'description': 'Allowed headers for CORS requests',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Access-Control-Max-Age': {
        'description': 'CORS preflight caching duration',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Access-Control-Allow-Credentials': {
        'description': 'Permission for credentialed cross-origin sharing',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'X-Download-Options': {
        'description': 'Protection against file download attacks',
        'good_values': ['noopen'],
        'score': 3,
        'type': 'presence'
    },
    'X-Permitted-Cross-Domain-Policies': {
        'description': 'Cross-domain policy for Adobe products',
        'good_values': ['none', 'master-only', 'by-content-type'],
        'score': 2,
        'type': 'presence'
    },
    'X-Requested-With': {
        'description': 'AJAX request convention (informational only)',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'X-UA-Compatible': {
        'description': 'Legacy browser compatibility (informational only)',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Server': {
        'description': 'Information about web server (should be hidden for security)',
        'good_values': [],
        'score': 2,
        'type': 'absence'
    },
    'X-Powered-By': {
        'description': 'Information about technologies used (should be hidden)',
        'good_values': [],
        'score': 2,
        'type': 'absence'
    },
    'Cache-Control': {
        'description': 'Context-dependent HTTP caching policy',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Set-Cookie': {
        'description': 'Cookie security settings',
        'good_values': ['Secure', 'HttpOnly', 'SameSite'],
        'score': 4,
        'type': 'flags'
    },
    'Clear-Site-Data': {
        'description': 'Optional browser data-clearing request',
        'good_values': [],
        'score': 0,
        'type': 'informational'
    },
    'Cross-Origin-Embedder-Policy': {
        'description': 'Cross-origin embedder policy',
        'good_values': ['require-corp'],
        'score': 3,
        'type': 'presence'
    },
    'Cross-Origin-Opener-Policy': {
        'description': 'Cross-origin opener policy',
        'good_values': ['same-origin'],
        'score': 3,
        'type': 'presence'
    },
    'Cross-Origin-Resource-Policy': {
        'description': 'Cross-origin resource policy',
        'good_values': ['same-origin', 'same-site'],
        'score': 3,
        'type': 'presence'
    }
}

def get_headers(
    url: str, timeout: int = 10,
    user_agent: str = 'Security-Header-Checker/0.0.6',
    follow_redirects: bool = True, max_redirects: int = 5,
    verify_ssl: bool = True
) -> Dict[str, str]:
    """Compatibility wrapper returning the detached, mapping-compatible snapshot."""
    return fetch_response(url, timeout=timeout, user_agent=user_agent,
                          follow_redirects=follow_redirects,
                          max_redirects=max_redirects, verify_ssl=verify_ssl)

# Analyze headers from the site
def analyze_header(header_name: str, header_value: str) -> Tuple[int, str, str]:
    """Single-value helper; HSTS/data clearing assume HTTPS, CORS lacks sibling fields."""

    if header_name not in SECURE_HEADERS:
        return 0, "INFO", f"Unknown header: {header_name}"

    if header_name in LEGACY_HEADERS:
        result = analyze_legacy(header_name, [header_value] if header_value else [])
        return result['score'], result['status'], result['description']
    if header_name in CORS_HEADERS:
        result = analyze_cors({header_name.lower(): [header_value] if header_value else []})[header_name]
        return result['score'], result['status'], result['description']
    special = {
        'Strict-Transport-Security': lambda: analyze_hsts([header_value], 'https://header-only.invalid'),
        'Content-Security-Policy': lambda: analyze_csp([header_value]),
        'Set-Cookie': lambda: analyze_cookies([header_value]),
        'X-Frame-Options': lambda: analyze_framing([header_value], []),
        'Cache-Control': lambda: analyze_cache_control([header_value] if header_value else []),
        'Clear-Site-Data': lambda: analyze_clear_site_data([header_value] if header_value else [], 'https://header-only.invalid'),
    }
    if header_name in special:
        result = special[header_name]()
        return result['score'], result['status'], result['description']
    header_info = SECURE_HEADERS[header_name]
    header_type = header_info.get('type', 'presence')  
    
    if header_type == 'absence':
        
        return 0, "BAD", f"❌ {header_info['description']} - should be hidden"
    
    else:  
        
        value = header_value.lower()
        for good_value in header_info['good_values']:
            if good_value.lower() in value:
                return header_info['score'], "GOOD", f"✅ {header_info['description']}"
        
        return 0, "BAD", f"❌ {header_info['description']}"
    

def check_security_headers(
    url: str, timeout: int = 10,
    user_agent: str = 'Security-Header-Checker/0.0.6',
    follow_redirects: bool = True, max_redirects: int = 5,
    verify_ssl: bool = True, *, snapshot=None, http_error=None
) -> Dict:
    """Analyze an existing snapshot or fetch once when called independently."""
    if http_error is not None:
        return {'success': False, 'url': url, 'error': http_error}
    if snapshot is None:
        try:
            snapshot = get_headers(url, timeout=timeout, user_agent=user_agent,
                                   follow_redirects=follow_redirects,
                                   max_redirects=max_redirects, verify_ssl=verify_ssl)
        except requests.exceptions.RequestException as exc:
            return {'success': False, 'url': url,
                    'error': f'{type(exc).__name__}: {exc}'}
    headers = requests.structures.CaseInsensitiveDict(snapshot)
    final_url = getattr(snapshot, 'final_url', url)
    def values(name):
        if isinstance(snapshot, HeaderSnapshot):
            return snapshot.get_values(name)
        # Mapping-only library input is one field, never split cookies on commas.
        return [headers[name]] if name in headers else []
    results = {
        'success': True, 'url': url, 'final_url': final_url,
        'total_score': 0, 'max_score': 0, 'headers': {},
        'header_values': (snapshot.values_by_name if isinstance(snapshot, HeaderSnapshot)
                          else {name.lower(): [value] for name, value in headers.items()}),
        'summary': {'good': 0, 'bad': 0, 'info': 0, 'warning': 0},
    }
    specials = {
        'Strict-Transport-Security': lambda: analyze_hsts(values('Strict-Transport-Security'), final_url),
        'Content-Security-Policy': lambda: analyze_csp(values('Content-Security-Policy')),
        'Set-Cookie': lambda: analyze_cookies(values('Set-Cookie')),
        'X-Frame-Options': lambda: analyze_framing(values('X-Frame-Options'), values('Content-Security-Policy')),
        'Cache-Control': lambda: analyze_cache_control(values('Cache-Control')),
        'Clear-Site-Data': lambda: analyze_clear_site_data(values('Clear-Site-Data'), final_url),
    }
    cors = analyze_cors({name.lower(): values(name) for name in CORS_HEADERS}, values('Vary'))
    for name, config in SECURE_HEADERS.items():
        if name in LEGACY_HEADERS:
            result = analyze_legacy(name, values(name))
        elif name in cors:
            result = cors[name]
        elif name in specials:
            result = specials[name]()
        else:
            if name in headers:
                score, status, description = analyze_header(name, headers[name])
                value = headers[name]
            elif config.get('type') == 'absence':
                score, status, description = config['score'], 'GOOD', config['description'] + ' - properly hidden'
                value = 'Not found'
            else:
                score, status, description = 0, 'BAD', config['description'] + ' - not found'
                value = 'Not found'
            result = {'value': value, 'score': score, 'status': status, 'description': description}
        results['headers'][name] = result
        results['total_score'] += result['score']
        if result.get('applicable', True):
            results['max_score'] += config['score']
        results['summary'][result['status'].lower()] += 1
    if values('Content-Security-Policy-Report-Only'):
        report_only = analyze_csp(values('Content-Security-Policy-Report-Only'), report_only=True)
        results['headers']['Content-Security-Policy-Report-Only'] = report_only
        results['summary']['info'] += 1
    results['percentage'] = (round(results['total_score'] / results['max_score'] * 100, 1)
                             if results['max_score'] else None)
    return results


def print_verbose_header_info(header_name: str, header_data: Dict, verbose: bool = False):
    if not verbose:
        return
    
    if header_name in LEGACY_HEADERS:
        print(LEGACY_HEADERS[header_name])
        return
    if header_name in CONTEXTUAL_HEADERS:
        print(f"Parsed {header_name}: {header_data.get('parsed', {})}")
        print('Context-dependent policy; excluded from the security score.')
        return
    if 'findings' in header_data:
        print(f"Parsed {header_name}: {header_data.get('parsed', {})}")
        print(f"Applicable to score: {header_data['applicable']}")
        return
    print(f"\n{Fore.CYAN}🔍 Detailed Analysis: {header_name}{Style.RESET_ALL}")
    print("-" * 50)
    
    print(f"Current Value: {header_data['value']}")
    
    status_color = Fore.GREEN if header_data['status'] == 'GOOD' else Fore.RED
    print(f"Status: {status_color}{header_data['status']}{Style.RESET_ALL}")
    print(f"Score: {header_data['score']} points")
    
    print(f"\n{Fore.YELLOW}Purpose:{Style.RESET_ALL}")
    print(f"  {header_data['description']}")
    
    if header_data['status'] != 'GOOD':
        print(f"\n{Fore.GREEN}Recommended Values:{Style.RESET_ALL}")
        if header_name == 'Strict-Transport-Security':
            print("  - max-age=31536000; includeSubDomains; preload")
            print("  - max-age=63072000; includeSubDomains; preload")
        elif header_name == 'Content-Security-Policy':
            print("  - default-src 'self'; script-src 'self'")
            print("  - object-src 'none'; base-uri 'self'")
        elif header_name == 'X-Frame-Options':
            print("  - DENY (most secure)")
            print("  - SAMEORIGIN (if frames needed)")
        elif header_name == 'X-Content-Type-Options':
            print("  - nosniff")
        elif header_name == 'Referrer-Policy':
            print("  - strict-origin-when-cross-origin")
            print("  - strict-origin")
        elif header_name == 'Permissions-Policy':
            print("  - geolocation=(), microphone=()")
        elif header_name == 'X-Download-Options':
            print("  - noopen")
        elif header_name == 'X-Permitted-Cross-Domain-Policies':
            print("  - none (most secure)")
            print("  - master-only")
        elif header_name == 'Set-Cookie':
            print("  - Secure; HttpOnly; SameSite=Strict")
        elif header_name == 'Cross-Origin-Embedder-Policy':
            print("  - require-corp")
        elif header_name == 'Cross-Origin-Opener-Policy':
            print("  - same-origin")
        elif header_name == 'Cross-Origin-Resource-Policy':
            print("  - same-origin")
    
    print(f"\n{Fore.BLUE}Technical Details:{Style.RESET_ALL}")
    if header_name == 'Strict-Transport-Security':
        print("  - max-age: Time in seconds to enforce HTTPS")
        print("  - includeSubDomains: Apply to all subdomains")
        print("  - preload: Include in browser HSTS lists")
    elif header_name == 'Content-Security-Policy':
        print("  - default-src: Default source for resources")
        print("  - script-src: Allowed sources for scripts")
        print("  - object-src: Allowed sources for objects")
    elif header_name == 'X-Frame-Options':
        print("  - DENY: Completely prevents framing")
        print("  - SAMEORIGIN: Allows framing from same origin")
        print("  - ALLOW-FROM: Allows framing from specific URI")
    elif header_name == 'X-Content-Type-Options':
        print("  - nosniff: Prevents MIME type sniffing")
        print("  - Forces browser to use declared Content-Type")
    elif header_name == 'Referrer-Policy':
        print("  - Controls what referrer information is sent")
        print("  - strict-origin: Only send origin, not full URL")
    elif header_name == 'Permissions-Policy':
        print("  - Controls access to browser features")
        print("  - geolocation=(): Disables geolocation")
    elif header_name == 'Set-Cookie':
        print("  - Secure: Only sent over HTTPS")
        print("  - HttpOnly: Not accessible via JavaScript")
        print("  - SameSite: Controls cross-site requests")
    elif header_name == 'Cross-Origin-Embedder-Policy':
        print("  - require-corp: Requires cross-origin resources to be CORS-enabled")
    elif header_name == 'Cross-Origin-Opener-Policy':
        print("  - same-origin: Isolates browsing context to same origin")
    elif header_name == 'Cross-Origin-Resource-Policy':
        print("  - same-origin: Only same-origin can load the resource")
    elif header_name == 'X-Download-Options':
        print("  - Prevents IE from executing downloaded files")
        print("  - noopen value prevents automatic execution")
        print("  - Protects against file download attacks")
    elif header_name == 'X-Permitted-Cross-Domain-Policies':
        print("  - Controls Adobe product cross-domain policies")
        print("  - none: Most secure, no cross-domain access")
        print("  - master-only: Only master policy files allowed")
    print(f"\n{Fore.MAGENTA}Examples:{Style.RESET_ALL}")
    if header_name == 'Strict-Transport-Security':
        print("  Apache (.htaccess):")
        print("    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"")
        print("  Nginx:")
        print("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;")
    elif header_name == 'Content-Security-Policy':
        print("  Basic CSP:")
        print("    Content-Security-Policy: default-src 'self'; script-src 'self'")
        print("  Strict CSP:")
        print("    Content-Security-Policy: default-src 'none'; script-src 'self'")
    elif header_name == 'X-Frame-Options':
        print("  Apache:")
        print("    Header always set X-Frame-Options \"DENY\"")
        print("  Nginx:")
        print("    add_header X-Frame-Options \"DENY\" always;")
    elif header_name == 'X-Content-Type-Options':
        print("  Apache:")
        print("    Header always set X-Content-Type-Options \"nosniff\"")
        print("  Nginx:")
        print("    add_header X-Content-Type-Options \"nosniff\" always;")
    elif header_name == 'Referrer-Policy':
        print("  Apache:")
        print("    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"")
        print("  Nginx:")
        print("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;")
    elif header_name == 'Permissions-Policy':
        print("  Apache:")
        print("    Header always set Permissions-Policy \"geolocation=(), microphone=()\"")
        print("  Nginx:")
        print("    add_header Permissions-Policy \"geolocation=(), microphone=()\" always;")
    elif header_name == 'X-Download-Options':
        print("  Apache:")
        print("    Header always set X-Download-Options \"noopen\"")
        print("  Nginx:")
        print("    add_header X-Download-Options \"noopen\" always;")
    elif header_name == 'X-Permitted-Cross-Domain-Policies':
        print("  Apache:")
        print("    Header always set X-Permitted-Cross-Domain-Policies \"none\"")
        print("  Nginx:")
        print("    add_header X-Permitted-Cross-Domain-Policies \"none\" always;")
    elif header_name == 'Set-Cookie':
        print("  Express.js:")
        print("    res.cookie('session', 'abc123', { secure: true, httpOnly: true, sameSite: 'strict' })")
        print("  Django:")
        print("    SESSION_COOKIE_SECURE = True")
        print("    SESSION_COOKIE_HTTPONLY = True")
    elif header_name == 'Cross-Origin-Embedder-Policy':
        print("  Apache:")
        print("    Header always set Cross-Origin-Embedder-Policy \"require-corp\"")
        print("  Nginx:")
        print("    add_header Cross-Origin-Embedder-Policy \"require-corp\" always;")
    elif header_name == 'Cross-Origin-Opener-Policy':
        print("  Apache:")
        print("    Header always set Cross-Origin-Opener-Policy \"same-origin\"")
        print("  Nginx:")
        print("    add_header Cross-Origin-Opener-Policy \"same-origin\" always;")
    elif header_name == 'Cross-Origin-Resource-Policy':
        print("  Apache:")
        print("    Header always set Cross-Origin-Resource-Policy \"same-origin\"")
        print("  Nginx:")
        print("    add_header Cross-Origin-Resource-Policy \"same-origin\" always;")




