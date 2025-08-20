
import requests
from typing import Dict, List, Optional
from colorama import Fore, Style
from typing import Tuple,List,Dict,Optional

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
        'description': 'Protection against clickjacking',
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
        'description': 'Protection against XSS attacks',
        'good_values': ['1', '1; mode=block'],
        'score': 5,
        'type': 'presence'
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
        'good_values': ['*', 'https://', 'http://'],
        'score': 3,
        'type': 'presence'
    },
    'Access-Control-Allow-Methods': {
        'description': 'Allowed HTTP methods for CORS',
        'good_values': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'score': 2,
        'type': 'presence'
    },
    'Access-Control-Allow-Headers': {
        'description': 'Allowed headers for CORS requests',
        'good_values': ['Content-Type', 'Authorization', 'X-Requested-With'],
        'score': 2,
        'type': 'presence'
    },
    'Access-Control-Max-Age': {
        'description': 'CORS preflight caching duration',
        'good_values': ['86400', '3600', '1800'],
        'score': 2,
        'type': 'presence'
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
        'description': 'Identifies AJAX requests',
        'good_values': ['XMLHttpRequest'],
        'score': 1,
        'type': 'presence'
    },
    'X-UA-Compatible': {
        'description': 'Browser compatibility mode',
        'good_values': ['IE=edge', 'chrome=1'],
        'score': 1,
        'type': 'presence'
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
        'description': 'Cache control policy for security',
        'good_values': ['no-store', 'no-cache', 'private'],
        'score': 3,
        'type': 'presence'
    },
    'Set-Cookie': {
        'description': 'Cookie security settings',
        'good_values': ['Secure', 'HttpOnly', 'SameSite'],
        'score': 4,
        'type': 'flags'
    },
    'Clear-Site-Data': {
        'description': 'Clear site data policy',
        'good_values': ['cache', 'cookies', 'storage'],
        'score': 3,
        'type': 'presence'
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
    header_type = header_info.get('type', 'presence')  
    
    if header_type == 'absence':
        
        return 0, "BAD", f"❌ {header_info['description']} - should be hidden"
    
    elif header_type == 'flags':
        
        value = header_value.lower()
        found_flags = 0
        for flag in header_info['good_values']:
            if flag.lower() in value:
                found_flags += 1
        
        if found_flags >= 2: 
            return header_info['score'], "GOOD", f"✅ {header_info['description']}"
        elif found_flags >= 1:
            return header_info['score'] // 2, "WARNING", f"⚠️ {header_info['description']} - partial security"
        else:
            return 0, "BAD", f"❌ {header_info['description']} - no security flags"
    
    else:  
        
        value = header_value.lower()
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
        header_info = SECURE_HEADERS[header_name]
        header_type = header_info.get('type', 'presence')
        
        if header_name in headers:
            if header_type == 'absence':
                
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
            if header_type == 'absence':
                results['headers'][header_name] = {
                    'value': 'Not found',
                    'score': header_info['score'],
                    'status': 'GOOD',
                    'description': f"✅ {header_info['description']} - properly hidden",
                }
                results['total_score'] += header_info['score']
                results['summary']['good'] += 1
            else:
                results['headers'][header_name] = {
                    'value': 'Not found',
                    'score': 0,
                    'status': 'BAD',
                    'description': f"❌ {header_info['description']} - not found",
                }
                results['summary']['bad'] += 1
    
    return results


def print_verbose_header_info(header_name: str, header_data: Dict, verbose: bool = False):
    if not verbose:
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
        elif header_name == 'X-XSS-Protection':
            print("  - 1; mode=block")
        elif header_name == 'Referrer-Policy':
            print("  - strict-origin-when-cross-origin")
            print("  - strict-origin")
        elif header_name == 'Permissions-Policy':
            print("  - geolocation=(), microphone=()")
        elif header_name == 'Access-Control-Allow-Origin':
            print("  - * (allow all origins)")
            print("  - https://example.com (specific origin)")
        elif header_name == 'Access-Control-Allow-Methods':
            print("  - GET, POST, OPTIONS")
            print("  - GET, POST, PUT, DELETE, OPTIONS")
        elif header_name == 'Access-Control-Allow-Headers':
            print("  - Content-Type, Authorization")
            print("  - Content-Type, Authorization, X-Requested-With")
        elif header_name == 'Access-Control-Max-Age':
            print("  - 86400 (24 hours)")
            print("  - 3600 (1 hour)")
        elif header_name == 'X-Download-Options':
            print("  - noopen")
        elif header_name == 'X-Permitted-Cross-Domain-Policies':
            print("  - none (most secure)")
            print("  - master-only")
        elif header_name == 'X-Requested-With':
            print("  - XMLHttpRequest")
        elif header_name == 'X-UA-Compatible':
            print("  - IE=edge")
            print("  - IE=edge,chrome=1")
        elif header_name == 'Cache-Control':
            print("  - no-store, no-cache, must-revalidate")
        elif header_name == 'Set-Cookie':
            print("  - Secure; HttpOnly; SameSite=Strict")
        elif header_name == 'Clear-Site-Data':
            print("  - \"cache\", \"cookies\", \"storage\"")
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
    elif header_name == 'X-XSS-Protection':
        print("  - 1: Enables XSS protection")
        print("  - mode=block: Blocks the page if XSS detected")
    elif header_name == 'Referrer-Policy':
        print("  - Controls what referrer information is sent")
        print("  - strict-origin: Only send origin, not full URL")
    elif header_name == 'Permissions-Policy':
        print("  - Controls access to browser features")
        print("  - geolocation=(): Disables geolocation")
    elif header_name == 'Cache-Control':
        print("  - no-store: Don't store in any cache")
        print("  - no-cache: Validate with server before using")
    elif header_name == 'Set-Cookie':
        print("  - Secure: Only sent over HTTPS")
        print("  - HttpOnly: Not accessible via JavaScript")
        print("  - SameSite: Controls cross-site requests")
    elif header_name == 'Clear-Site-Data':
        print("  - Clears browser data on logout")
        print("  - cache: Clears cached resources")
        print("  - cookies: Clears cookies")
    elif header_name == 'Cross-Origin-Embedder-Policy':
        print("  - require-corp: Requires cross-origin resources to be CORS-enabled")
    elif header_name == 'Cross-Origin-Opener-Policy':
        print("  - same-origin: Isolates browsing context to same origin")
    elif header_name == 'Cross-Origin-Resource-Policy':
        print("  - same-origin: Only same-origin can load the resource")
    elif header_name == 'Access-Control-Allow-Origin':
        print("  - Controls which origins can access the resource")
        print("  - * allows all origins (less secure)")
        print("  - Specific origin is more secure")
    elif header_name == 'Access-Control-Allow-Methods':
        print("  - Specifies allowed HTTP methods for CORS")
        print("  - GET, POST, OPTIONS are common")
        print("  - Include only necessary methods")
    elif header_name == 'Access-Control-Allow-Headers':
        print("  - Specifies allowed headers in CORS requests")
        print("  - Content-Type and Authorization are common")
        print("  - X-Requested-With for AJAX detection")
    elif header_name == 'Access-Control-Max-Age':
        print("  - Caches preflight response for specified seconds")
        print("  - Reduces number of preflight requests")
        print("  - 86400 seconds (24 hours) is common")
    elif header_name == 'X-Download-Options':
        print("  - Prevents IE from executing downloaded files")
        print("  - noopen value prevents automatic execution")
        print("  - Protects against file download attacks")
    elif header_name == 'X-Permitted-Cross-Domain-Policies':
        print("  - Controls Adobe product cross-domain policies")
        print("  - none: Most secure, no cross-domain access")
        print("  - master-only: Only master policy files allowed")
    elif header_name == 'X-Requested-With':
        print("  - Identifies AJAX requests")
        print("  - XMLHttpRequest is standard value")
        print("  - Helps server distinguish AJAX from regular requests")
    elif header_name == 'X-UA-Compatible':
        print("  - Forces IE to use latest rendering engine")
        print("  - IE=edge uses latest available version")
        print("  - chrome=1 enables Chrome Frame if available")
    
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
    elif header_name == 'X-XSS-Protection':
        print("  Apache:")
        print("    Header always set X-XSS-Protection \"1; mode=block\"")
        print("  Nginx:")
        print("    add_header X-XSS-Protection \"1; mode=block\" always;")
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
    elif header_name == 'Access-Control-Allow-Origin':
        print("  Apache:")
        print("    Header always set Access-Control-Allow-Origin \"*\"")
        print("  Nginx:")
        print("    add_header Access-Control-Allow-Origin \"*\" always;")
    elif header_name == 'Access-Control-Allow-Methods':
        print("  Apache:")
        print("    Header always set Access-Control-Allow-Methods \"GET, POST, OPTIONS\"")
        print("  Nginx:")
        print("    add_header Access-Control-Allow-Methods \"GET, POST, OPTIONS\" always;")
    elif header_name == 'Access-Control-Allow-Headers':
        print("  Apache:")
        print("    Header always set Access-Control-Allow-Headers \"Content-Type, Authorization\"")
        print("  Nginx:")
        print("    add_header Access-Control-Allow-Headers \"Content-Type, Authorization\" always;")
    elif header_name == 'Access-Control-Max-Age':
        print("  Apache:")
        print("    Header always set Access-Control-Max-Age \"86400\"")
        print("  Nginx:")
        print("    add_header Access-Control-Max-Age \"86400\" always;")
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
    elif header_name == 'X-Requested-With':
        print("  Express.js:")
        print("    res.setHeader('X-Requested-With', 'XMLHttpRequest')")
        print("  Django:")
        print("    response['X-Requested-With'] = 'XMLHttpRequest'")
    elif header_name == 'X-UA-Compatible':
        print("  Apache:")
        print("    Header always set X-UA-Compatible \"IE=edge\"")
        print("  Nginx:")
        print("    add_header X-UA-Compatible \"IE=edge\" always;")
    elif header_name == 'Cache-Control':
        print("  Apache:")
        print("    Header always set Cache-Control \"no-store, no-cache, must-revalidate\"")
        print("  Nginx:")
        print("    add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;")
    elif header_name == 'Set-Cookie':
        print("  Express.js:")
        print("    res.cookie('session', 'abc123', { secure: true, httpOnly: true, sameSite: 'strict' })")
        print("  Django:")
        print("    SESSION_COOKIE_SECURE = True")
        print("    SESSION_COOKIE_HTTPONLY = True")
    elif header_name == 'Clear-Site-Data':
        print("  Apache:")
        print("    Header always set Clear-Site-Data \"\\\"cache\\\", \\\"cookies\\\", \\\"storage\\\"\"")
        print("  Nginx:")
        print("    add_header Clear-Site-Data \"\\\"cache\\\", \\\"cookies\\\", \\\"storage\\\"\" always;")
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




