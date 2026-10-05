"""
Module for generating security recommendations
"""

from typing import Dict, List
from colorama import Fore, Style
from .header_rules import LEGACY_HEADERS, CORS_HEADERS, CONTEXTUAL_HEADERS

class SecurityRecommendations:
    def __init__(self):
        self.recommendations = {
            'Strict-Transport-Security': {
                'missing': [
                    "❌ HSTS header is missing",
                    "🔧 Add Strict-Transport-Security header to force HTTPS",
                    "📝 Example: max-age=31536000 (includeSubDomains/preload are optional)",
                    "⚠️ Warning: Once enabled, HTTPS cannot be disabled for max-age period"
                ],
                'weak': [
                    "⚠️ HSTS max-age is too short",
                    "🔧 Increase max-age to at least 31536000 (1 year)",
                    "📝 Recommended: max-age=63072000 (includeSubDomains/preload are optional)"
                ]
            },
            'Content-Security-Policy': {
                'missing': [
                    "❌ CSP header is missing",
                    "🔧 Add Content-Security-Policy header to prevent XSS",
                    "📝 Basic example: default-src 'self'; script-src 'self'",
                    "📚 Learn more: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                ],
                'weak': [
                    "⚠️ CSP policy is too permissive",
                    "🔧 Tighten CSP policy to restrict resource loading",
                    "📝 Remove 'unsafe-inline' and 'unsafe-eval' if possible"
                ]
            },
            'X-Frame-Options': {
                'missing': [
                    "❌ X-Frame-Options header is missing",
                    "🔧 Add X-Frame-Options to prevent clickjacking",
                    "📝 Recommended: X-Frame-Options: DENY",
                    "📝 Alternative: X-Frame-Options: SAMEORIGIN"
                ]
            },
            'X-Content-Type-Options': {
                'missing': [
                    "❌ X-Content-Type-Options header is missing",
                    "🔧 Add X-Content-Type-Options: nosniff",
                    "🔧 Prevents MIME type sniffing attacks"
                ]
            },

            'Referrer-Policy': {
                'missing': [
                    "❌ Referrer-Policy header is missing",
                    "🔧 Add Referrer-Policy to control referrer information",
                    "📝 Recommended: Referrer-Policy: strict-origin-when-cross-origin"
                ]
            },
            'Permissions-Policy': {
                'missing': [
                    "❌ Permissions-Policy header is missing",
                    "🔧 Add Permissions-Policy to control browser features",
                    "📝 Example: Permissions-Policy: geolocation=(), microphone=()"
                ]
            },
            'Server': {
                'present': [
                    "⚠️ Server header reveals server information",
                    "🔧 Remove or modify Server header to hide server details",
                    "📝 This helps prevent information disclosure attacks"
                ]
            },
            'X-Powered-By': {
                'present': [
                    "⚠️ X-Powered-By header reveals technology stack",
                    "🔧 Remove X-Powered-By header to hide technology information",
                    "📝 This prevents technology fingerprinting"
                ]
            },
            'Set-Cookie': {
                'weak': [
                    "⚠️ Cookies lack security flags",
                    "🔧 Use Secure and explicit SameSite; use HttpOnly when JavaScript access is not required",
                    "📝 Example: Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict"
                ]
            },
            'Cross-Origin-Embedder-Policy': {
                'missing': [
                    "❌ Cross-Origin-Embedder-Policy header is missing",
                    "🔧 Add COEP for enhanced security isolation",
                    "📝 Example: Cross-Origin-Embedder-Policy: require-corp"
                ]
            },
            'Cross-Origin-Opener-Policy': {
                'missing': [
                    "❌ Cross-Origin-Opener-Policy header is missing",
                    "🔧 Add COOP to isolate browsing context",
                    "📝 Example: Cross-Origin-Opener-Policy: same-origin"
                ]
            },
            'Cross-Origin-Resource-Policy': {
                'missing': [
                    "❌ Cross-Origin-Resource-Policy header is missing",
                    "🔧 Add CORP to control resource loading",
                    "📝 Example: Cross-Origin-Resource-Policy: same-origin"
                ]
            },
            'X-Download-Options': {
                'missing': [
                    "❌ X-Download-Options header is missing",
                    "🔧 Add protection against file download attacks",
                    "📝 Example: X-Download-Options: noopen"
                ]
            },
            'X-Permitted-Cross-Domain-Policies': {
                'missing': [
                    "❌ X-Permitted-Cross-Domain-Policies header is missing",
                    "🔧 Add cross-domain policy for Adobe products",
                    "📝 Example: X-Permitted-Cross-Domain-Policies: none"
                ]
            },


        }
    
    def get_recommendations_for_header(self, header_name: str, status: str, value: str) -> List[str]:
        if header_name in LEGACY_HEADERS:
            return [LEGACY_HEADERS[header_name]]
        if header_name in CORS_HEADERS:
            return ['CORS is optional; choose sharing rules for the intended clients.',
                    'Wildcard does not authorize credentialed sharing; a GET without Origin or preflight does not verify CORS.',
                    'Use Vary: Origin only when the policy varies with the request Origin.']
        if header_name == 'Cache-Control':
            return ['Choose caching rules according to resource sensitivity and purpose.',
                    'no-cache allows storage with validation; no-store forbids storage; private still permits browser storage.']
        if header_name == 'Clear-Site-Data':
            return ['Data clearing is optional and requires a potentially trustworthy origin.',
                    'Use it only where clearing is intended; do not add it to every response. Browser execution is not verified.']
        if header_name not in self.recommendations:
            return []
        
        if status == 'BAD':
            if not value or value == 'None':
                return self.recommendations[header_name].get('missing', [])
            else:
                return self.recommendations[header_name].get('weak', [])
        elif status == 'INFO' and (header_name == 'Server' or header_name == 'X-Powered-By'):
            return self.recommendations[header_name].get('present', [])
        
        return []
    
    def get_implementation_examples(self, header_name: str) -> Dict:
        if header_name in LEGACY_HEADERS or header_name in CONTEXTUAL_HEADERS:
            return {}
        examples = {
            'Strict-Transport-Security': {
                'Apache': [
                    "# .htaccess file",
                    "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                    "",
                    "# httpd.conf",
                    "<VirtualHost *:443>",
                    "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                    "</VirtualHost>"
                ],
                'Nginx': [
                    "# nginx.conf",
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                    "",
                    "# server block",
                    "server {",
                    "    listen 443 ssl;",
                    "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                    "}"
                ],
                'Express.js': [
                    "const helmet = require('helmet');",
                    "app.use(helmet.hsts({",
                    "    maxAge: 31536000,",
                    "    includeSubDomains: true,",
                    "    preload: true",
                    "}));"
                ],
                'Django': [
                    "# settings.py",
                    "SECURE_HSTS_SECONDS = 31536000",
                    "SECURE_HSTS_INCLUDE_SUBDOMAINS = True",
                    "SECURE_HSTS_PRELOAD = True"
                ]
            },
            'Content-Security-Policy': {
                'Apache': [
                    "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'\""
                ],
                'Nginx': [
                    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.contentSecurityPolicy({",
                    "    directives: {",
                    "        defaultSrc: [\"'self'\"],",
                    "        scriptSrc: [\"'self'\"]",
                    "    }",
                    "}));"
                ],
                'Django': [
                    "# settings.py",
                    "CSP_DEFAULT_SRC = (\"'self'\",)",
                    "CSP_SCRIPT_SRC = (\"'self'\",)"
                ]
            },
            'X-Frame-Options': {
                'Apache': [
                    "Header always set X-Frame-Options \"DENY\""
                ],
                'Nginx': [
                    "add_header X-Frame-Options \"DENY\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.frameguard({ action: 'deny' }));"
                ],
                'Django': [
                    "# settings.py",
                    "X_FRAME_OPTIONS = 'DENY'"
                ]
            },
            'X-Content-Type-Options': {
                'Apache': [
                    "Header always set X-Content-Type-Options \"nosniff\""
                ],
                'Nginx': [
                    "add_header X-Content-Type-Options \"nosniff\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.noSniff());"
                ],
                'Django': [
                    "# settings.py",
                    "SECURE_CONTENT_TYPE_NOSNIFF = True"
                ]
            },

            'Referrer-Policy': {
                'Apache': [
                    "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
                ],
                'Nginx': [
                    "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));"
                ],
                'Django': [
                    "# settings.py",
                    "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'"
                ]
            },
            'Permissions-Policy': {
                'Apache': [
                    "Header always set Permissions-Policy \"geolocation=(), microphone=()\""
                ],
                'Nginx': [
                    "add_header Permissions-Policy \"geolocation=(), microphone=()\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.permittedCrossDomainPolicies());"
                ]
            },
            'X-Download-Options': {
                'Apache': [
                    "Header always set X-Download-Options \"noopen\""
                ],
                'Nginx': [
                    "add_header X-Download-Options \"noopen\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.ieNoOpen());"
                ]
            },
            'X-Permitted-Cross-Domain-Policies': {
                'Apache': [
                    "Header always set X-Permitted-Cross-Domain-Policies \"none\""
                ],
                'Nginx': [
                    "add_header X-Permitted-Cross-Domain-Policies \"none\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.permittedCrossDomainPolicies());"
                ]
            },


        }
        
        return examples.get(header_name, {})
    
    def print_security_summary(self, results: Dict, verbose: bool = False):
        if not verbose:
            return
        
        print(f"\n{Fore.CYAN}🔧 Security Recommendations:{Style.RESET_ALL}")
        print("=" * 60)
        
        issues_found = 0
        for header_name, header_data in results['headers'].items():
            if 'findings' in header_data:
                issues_found += sum(item['status'] in ('BAD', 'WARNING') for item in header_data['findings'])
                continue
            if header_data['status'] in ['BAD', 'INFO']:
                recommendations = self.get_recommendations_for_header(
                    header_name, header_data['status'], header_data['value']
                )
                
                if recommendations:
                    issues_found += 1
                    print(f"\n{Fore.RED}🚨 {header_name}:{Style.RESET_ALL}")
                    for rec in recommendations:
                        print(f"  {rec}")
                    
                    examples = self.get_implementation_examples(header_name)
                    if examples:
                        print(f"\n  {Fore.YELLOW}Implementation Examples:{Style.RESET_ALL}")
                        for tech, code in examples.items():
                            print(f"    {Fore.BLUE}{tech}:{Style.RESET_ALL}")
                            for line in code:
                                print(f"      {line}")
        
        if issues_found == 0:
            print(f"\n{Fore.GREEN}🎉 No issues identified by these rules; this is not a full security audit.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}📊 Total issues found: {issues_found}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}💡 Review these findings in context; informational policies do not affect the score.{Style.RESET_ALL}")
