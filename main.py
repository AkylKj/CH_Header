#!/usr/bin/env python3

"""
Security Header Checker - CLI приложение для проверки безопасности сайтов
"""
# import libraries
import argparse
import requests
from colorama import init,Fore, Style
import urllib3
import sys
from datetime import datetime

# import custom modules
from src.header_checker import check_security_headers
from src.exporter import export_results
from src.ssl_checker import analyze_ssl_security

init(autoreset=True)

def main():
    # Main argument parser
    parser = argparse.ArgumentParser(
        description="Security Header Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python main.py https://example.com
        python main.py https://example.com --verbose
        python main.py https://example.com --output results.txt
        python main.py https://example.com --ssl-check
        python main.py https://example.com --ssl-only
        python main.py https://example.com --timeout 10
        python main.py https://example.com --user-agent "Example User-Agent"
        python main.py https://example.com --version
        """
        )
    
    # main options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output',
    )

    parser.add_argument(
        'url',
        nargs='?',
        help='URL of the website to check',
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file to save results',
    )
    
    # for future use
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=10,
        help='Timeout in seconds',
    )

    parser.add_argument(
        '--user-agent', '-u',
        help='User-Agent to use for the request',
        default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    )

    parser.add_argument(
        '--version', '-V',
        action='version',
        version='%(prog)s 0.0.1',
    )

    parser.add_argument(
        '--follow-redirects', '-f',
        action='store_true',
        help='Follow redirects',
    )

    parser.add_argument(
        '--no-redirects', '-n',
        action='store_true',
        help='Do not follow redirects',
    )



    # additional options

    parser.add_argument(
        '--max-redirects',
        type=int,
        default=5,
        help='Maximum number of redirects to follow (default: 5)',
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        default=True,
        help='Verify SSL certificates (default: True)',
    )

    # SSL/TLS analysis options
    parser.add_argument(
        '--ssl-check',
        action='store_true',
        help='Enable SSL/TLS security analysis',
    )

    parser.add_argument(
        '--ssl-only',
        action='store_true',
        help='Perform only SSL/TLS analysis (skip header checks)',
    )
    
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Do not verify SSL certificates',
    )
    
    args = parser.parse_args()


    if args.no_redirects:
        args.follow_redirects = False
    
    if args.no_verify_ssl:
        args.verify_ssl = False
    
    
    # check if url is provided
    if not args.url:
        print(f"{Fore.RED}Error: URL is required. Please provide a URL to check.{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    # check if url format is valid
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}Error: Invalid URL. Please provide a valid URL starting with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)


    # Determine what to check
    check_headers = not args.ssl_only
    check_ssl = args.ssl_check or args.ssl_only
    
    if check_headers:
        print(f"{Fore.CYAN}🔍 Checking the security of the site: {args.url}{Style.RESET_ALL}")
        
        # Display request settings in verbose mode
        if args.verbose:
            print(f"{Fore.CYAN}🔧 Request Settings:{Style.RESET_ALL}")
            print(f"  Timeout: {args.timeout} seconds")
            print(f"  User-Agent: {args.user_agent}")
            print(f"  Follow redirects: {args.follow_redirects}")
            print(f"  Max redirects: {args.max_redirects}")
            print(f"  Verify SSL: {args.verify_ssl}")
            print()

        # Check headers security with new parameters
        results = check_security_headers(
            args.url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            verify_ssl=args.verify_ssl
        )

        if not results['success']:
            print(f"{Fore.RED}❌ Error: {results['error']}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        results = None
    
    # SSL/TLS Analysis
    ssl_results = None
    if check_ssl:
        ssl_results = analyze_ssl_security(args.url, args.timeout)
    
    # Print results
    if check_headers and results:
        print(f"\n{Fore.GREEN}📊 Security Header Check Results:{Style.RESET_ALL}")
        print(f"URL: {results['url']}")
        print(f"Total Score: {results['total_score']}/{results['max_score']}")
        print(f"Security Percentage: {(results['total_score'] / results['max_score'] * 100):.1f}%")
    
    print(f"\n{Fore.YELLOW}📋 Detailed Report:{Style.RESET_ALL}")
    print("-" * 60)
    
    for header_name, header_data in results['headers'].items():
        status_color = Fore.GREEN if header_data['status'] == 'GOOD' else Fore.RED
        print(f"{header_name}:")
        print(f"  Value: {header_data['value']}")
        print(f"  Status: {status_color}{header_data['status']}{Style.RESET_ALL}")
        print(f"  Description: {header_data['description']}")
        print(f"  Score: {header_data['score']}")
        print()
    
    # Summary
    print(f"{Fore.CYAN}📈 Summary:{Style.RESET_ALL}")
    print(f"✅ Well configured: {results['summary']['good']}")
    print(f"❌ Issues: {results['summary']['bad']}")
    print(f"ℹ️ Info: {results['summary']['info']}")
    
    # Security assessment for headers
    if check_headers and results:
        percentage = (results['total_score'] / results['max_score']) * 100
        if percentage >= 80:
            print(f"\n{Fore.GREEN}🎉 Excellent header security!{Style.RESET_ALL}")
        elif percentage >= 60:
            print(f"\n{Fore.YELLOW}⚠️ Average header security{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}🚨 Low header security!{Style.RESET_ALL}")
    
    # SSL/TLS Results
    if check_ssl and ssl_results:
        print(f"\n{Fore.GREEN}🔒 SSL/TLS Security Results:{Style.RESET_ALL}")
        print(f"URL: {ssl_results['url']}")
        print(f"SSL Score: {ssl_results['score']['total_score']}/{ssl_results['score']['max_score']}")
        print(f"SSL Percentage: {ssl_results['score']['percentage']}%")
        print(f"Security Level: {ssl_results['score']['level_emoji']} {ssl_results['score']['security_level']}")
        
        print(f"\n{Fore.YELLOW}📋 SSL/TLS Details:{Style.RESET_ALL}")
        print("-" * 60)
        
        # Certificate information
        if ssl_results['certificate']['success']:
            cert = ssl_results['certificate']
            print(f"📜 Certificate Information:")
            print(f"  Subject: {cert.get('subject', {}).get('commonName', 'Unknown')}")
            print(f"  Issuer: {cert.get('issuer', {}).get('commonName', 'Unknown')}")
            print(f"  Expires: {cert.get('not_after', 'Unknown')}")
            print(f"  Valid: {'✅ Yes' if not cert.get('is_expired') else '❌ No'}")
            print(f"  Hostname Match: {'✅ Yes' if cert.get('hostname_valid') else '❌ No'}")
        
        # Protocol information
        if ssl_results['protocols']['success']:
            print(f"\n🛡️ TLS Protocols:")
            for protocol, info in ssl_results['protocols']['protocols'].items():
                status = "✅ Supported" if info['supported'] else "❌ Not supported"
                print(f"  {protocol}: {status}")
        
        # Cipher information
        if ssl_results['ciphers']['success']:
            ciphers = ssl_results['ciphers']
            print(f"\n🔐 Cipher Suites:")
            print(f"  Current Cipher: {ciphers.get('current_cipher', 'Unknown')}")
            print(f"  Cipher Version: {ciphers.get('cipher_version', 'Unknown')}")
            print(f"  Cipher Bits: {ciphers.get('cipher_bits', 'Unknown')}")
        
        # SSL Security assessment
        ssl_percentage = ssl_results['score']['percentage']
        if ssl_percentage >= 80:
            print(f"\n{Fore.GREEN}🎉 Excellent SSL/TLS security!{Style.RESET_ALL}")
        elif ssl_percentage >= 60:
            print(f"\n{Fore.YELLOW}⚠️ Average SSL/TLS security{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}🚨 Low SSL/TLS security!{Style.RESET_ALL}")
        

    # Save results to file
    if args.output:
        print(f"\n{Fore.CYAN}💾 Saving results to {args.output}...{Style.RESET_ALL}")
        
        # Combine results for export
        export_data = {
            'url': args.url,
            'headers': results if check_headers else None,
            'ssl': ssl_results if check_ssl else None,
            'timestamp': datetime.now().isoformat()
        }
        
        if export_results(export_data, args.output):
            print(f"{Fore.GREEN}✅ Results saved successfully!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Error: Failed to save results{Style.RESET_ALL}")

if __name__ == "__main__":
    main()