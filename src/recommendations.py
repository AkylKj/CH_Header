"""
Module for generating security recommendations
"""

from typing import Dict, List
from colorama import Fore, Style

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
            'X-XSS-Protection': {
                'missing': [
                    "❌ X-XSS-Protection header is missing",
                    "🔧 Add X-XSS-Protection: 1; mode=block",
                    "📝 Provides additional XSS protection for older browsers"
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
            'Cache-Control': {
                'missing': [
                    "❌ Cache-Control header is missing",
                    "🔧 Add Cache-Control for sensitive pages",
                    "📝 Example: Cache-Control: no-store, no-cache, must-revalidate"
                ]
            },
            'Set-Cookie': {
                'weak': [
                    "⚠️ Cookies lack security flags",
                    "🔧 Use Secure and explicit SameSite; use HttpOnly when JavaScript access is not required",
                    "📝 Example: Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict"
                ]
            },
            'Clear-Site-Data': {
                'missing': [
                    "❌ Clear-Site-Data header is missing",
                    "🔧 Add Clear-Site-Data for logout functionality",
                    "📝 Example: Clear-Site-Data: \"cache\", \"cookies\", \"storage\""
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
            'Access-Control-Allow-Origin': {
                'missing': [
                    "❌ Access-Control-Allow-Origin header is missing",
                    "🔧 Add CORS policy for cross-origin requests",
                    "📝 Example: Access-Control-Allow-Origin: *"
                ],
                'weak': [
                    "⚠️ Access-Control-Allow-Origin is too permissive",
                    "🔧 Use specific origin instead of * for better security",
                    "📝 Example: Access-Control-Allow-Origin: https://example.com"
                ]
            },
            'Access-Control-Allow-Methods': {
                'missing': [
                    "❌ Access-Control-Allow-Methods header is missing",
                    "🔧 Add allowed HTTP methods for CORS",
                    "📝 Example: Access-Control-Allow-Methods: GET, POST, OPTIONS"
                ]
            },
            'Access-Control-Allow-Headers': {
                'missing': [
                    "❌ Access-Control-Allow-Headers header is missing",
                    "🔧 Add allowed headers for CORS requests",
                    "📝 Example: Access-Control-Allow-Headers: Content-Type, Authorization"
                ]
            },
            'Access-Control-Max-Age': {
                'missing': [
                    "❌ Access-Control-Max-Age header is missing",
                    "🔧 Add CORS preflight caching for better performance",
                    "📝 Example: Access-Control-Max-Age: 86400"
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
            'X-Requested-With': {
                'missing': [
                    "❌ X-Requested-With header is missing",
                    "🔧 Add AJAX request identification",
                    "📝 Example: X-Requested-With: XMLHttpRequest"
                ]
            },
            'X-UA-Compatible': {
                'missing': [
                    "❌ X-UA-Compatible header is missing",
                    "🔧 Add browser compatibility mode",
                    "📝 Example: X-UA-Compatible: IE=edge"
                ]
            }
        }
    
    def get_recommendations_for_header(self, header_name: str, status: str, value: str) -> List[str]:
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
            'X-XSS-Protection': {
                'Apache': [
                    "Header always set X-XSS-Protection \"1; mode=block\""
                ],
                'Nginx': [
                    "add_header X-XSS-Protection \"1; mode=block\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.xssFilter());"
                ],
                'Django': [
                    "# settings.py",
                    "SECURE_BROWSER_XSS_FILTER = True"
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
            'Access-Control-Allow-Origin': {
                'Apache': [
                    "Header always set Access-Control-Allow-Origin \"*\""
                ],
                'Nginx': [
                    "add_header Access-Control-Allow-Origin \"*\" always;"
                ],
                'Express.js': [
                    "app.use(cors({ origin: '*' }));"
                ],
                'Django': [
                    "CORS_ALLOW_ALL_ORIGINS = True"
                ]
            },
            'Access-Control-Allow-Methods': {
                'Apache': [
                    "Header always set Access-Control-Allow-Methods \"GET, POST, OPTIONS\""
                ],
                'Nginx': [
                    "add_header Access-Control-Allow-Methods \"GET, POST, OPTIONS\" always;"
                ],
                'Express.js': [
                    "app.use(cors({ methods: ['GET', 'POST', 'OPTIONS'] }));"
                ]
            },
            'Access-Control-Allow-Headers': {
                'Apache': [
                    "Header always set Access-Control-Allow-Headers \"Content-Type, Authorization\""
                ],
                'Nginx': [
                    "add_header Access-Control-Allow-Headers \"Content-Type, Authorization\" always;"
                ],
                'Express.js': [
                    "app.use(cors({ allowedHeaders: ['Content-Type', 'Authorization'] }));"
                ]
            },
            'Access-Control-Max-Age': {
                'Apache': [
                    "Header always set Access-Control-Max-Age \"86400\""
                ],
                'Nginx': [
                    "add_header Access-Control-Max-Age \"86400\" always;"
                ],
                'Express.js': [
                    "app.use(cors({ maxAge: 86400 }));"
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
            'X-Requested-With': {
                'Express.js': [
                    "app.use((req, res, next) => {",
                    "    res.setHeader('X-Requested-With', 'XMLHttpRequest');",
                    "    next();",
                    "});"
                ],
                'Django': [
                    "response['X-Requested-With'] = 'XMLHttpRequest'"
                ]
            },
            'X-UA-Compatible': {
                'Apache': [
                    "Header always set X-UA-Compatible \"IE=edge\""
                ],
                'Nginx': [
                    "add_header X-UA-Compatible \"IE=edge\" always;"
                ],
                'Express.js': [
                    "app.use(helmet.ieNoOpen());"
                ]
            }
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
            print(f"{Fore.CYAN}💡 Fix these issues to improve your security score.{Style.RESET_ALL}")
