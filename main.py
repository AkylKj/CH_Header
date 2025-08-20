#!/usr/bin/env python3


# import libraries
import argparse
import requests
from colorama import init,Fore, Style
import urllib3
import sys
from datetime import datetime

# import custom modules
from src.header_checker import check_security_headers, print_verbose_header_info
from src.exporter import export_results
from src.ssl_checker import analyze_ssl_security
from src.bulk_checker import BulkChecker
from src.response_analyzer import ResponseAnalyzer
from src.recommendations import SecurityRecommendations

init(autoreset=True)

def main():
    # Main argument parser
    parser = argparse.ArgumentParser(
        description="Security Header Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        # Single site check
        python main.py https://example.com
        python main.py https://example.com --verbose
        python main.py https://example.com --output results.txt
        python main.py https://example.com --ssl-check
        python main.py https://example.com --ssl-only
        python main.py https://example.com --response-analysis
        python main.py https://example.com --response-only
        python main.py https://example.com --timeout 10
        python main.py https://example.com --user-agent "Example User-Agent"
        
        # Multiple sites check
        python main.py --urls "https://google.com,https://github.com,https://stackoverflow.com"
        python main.py --file urls.txt --parallel 5
        python main.py --file urls.txt --ssl-check --parallel 3 --output bulk_results.json
        python main.py --urls "https://example.com,https://test.com" --batch-size 10
        python main.py --file urls.txt --response-analysis --parallel 3
        
        python main.py https://example.com --version
        """
        )
    
    # main options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with detailed analysis, recommendations, and implementation examples',
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
        version='%(prog)s 0.0.2',
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

    # Response analysis options
    parser.add_argument(
        '--response-analysis',
        action='store_true',
        help='Enable detailed HTTP response analysis',
    )

    parser.add_argument(
        '--response-only',
        action='store_true',
        help='Perform only response analysis (skip other checks)',
    )

    # options for mass checking
    parser.add_argument(
        '--file','-f',
        help='File with URLs to check',
    )

    parser.add_argument(
        '--urls','-u',
        help='URLs to check',
    )

    parser.add_argument(
        '--parallel','-p',
        type=int,
        default=1,
        help='Number of parallel requests (default: 1)',
    )

    parser.add_argument(
        '--batch-size','-b',
        type=int,
        default=10,
        help='Number of requests in a batch (default: 10)',
    )

    
    
    
    
    args = parser.parse_args()


    if args.no_redirects:
        args.follow_redirects = False
    
    if args.no_verify_ssl:
        args.verify_ssl = False
    
    
    # Determine URLs to check
    urls_to_check = []
    
    if args.file:
        # Load URLs from file
        try:
            checker = BulkChecker(args.parallel, args.batch_size)
            urls_to_check = checker.load_urls_from_file(args.file)
            if not urls_to_check:
                print(f"{Fore.RED}Error: No valid URLs found in file {args.file}{Style.RESET_ALL}")
                sys.exit(1)
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {args.file} not found{Style.RESET_ALL}")
            sys.exit(1)
    elif args.urls:
        # Load URLs from comma-separated string
        checker = BulkChecker(args.parallel, args.batch_size)
        urls_to_check = checker.parse_urls_string(args.urls)
        if not urls_to_check:
            print(f"{Fore.RED}Error: No valid URLs provided in --urls argument{Style.RESET_ALL}")
            sys.exit(1)
    elif args.url:
        # Single URL (existing logic)
        if not args.url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}Error: Invalid URL. Please provide a valid URL starting with http:// or https://{Style.RESET_ALL}")
            sys.exit(1)
        urls_to_check = [args.url]
    else:
        print(f"{Fore.RED}Error: Please provide URL(s) via --url, --file, or --urls{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)


    # Determine what to check
    check_headers = not args.ssl_only and not args.response_only
    check_ssl = args.ssl_check or args.ssl_only
    check_response = args.response_analysis or args.response_only
    
    # Check multiple sites
    if len(urls_to_check) > 1:
        print(f"{Fore.CYAN}🔍 Checking {len(urls_to_check)} sites...{Style.RESET_ALL}")
        
        if args.verbose:
            print(f"{Fore.CYAN}🔧 Request Settings:{Style.RESET_ALL}")
            print(f"  Timeout: {args.timeout} seconds")
            print(f"  User-Agent: {args.user_agent}")
            print(f"  Follow redirects: {args.follow_redirects}")
            print(f"  Max redirects: {args.max_redirects}")
            print(f"  Verify SSL: {args.verify_ssl}")
            print(f"  Parallel workers: {args.parallel}")
            print(f"  Batch size: {args.batch_size}")
            print()
        
        # Perform bulk checks
        results_list = checker.check_multiple_sites(
            urls_to_check,
            check_ssl=check_ssl,
            timeout=args.timeout,
            user_agent=args.user_agent,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            verify_ssl=args.verify_ssl
        )
        
        # Add response analysis if requested
        if check_response:
            analyzer = ResponseAnalyzer()
            for result in results_list:
                if result['success']:
                    response_result = analyzer.analyze_response_headers(
                        result['url'],
                        timeout=args.timeout,
                        user_agent=args.user_agent,
                        follow_redirects=args.follow_redirects,
                        max_redirects=args.max_redirects,
                        verify_ssl=args.verify_ssl
                    )
                    result['response'] = response_result
        
        # Generate summary report
        summary = checker.generate_summary_report(results_list)
        
        # Display summary
        print(f"\n{Fore.GREEN}📊 Bulk Check Summary:{Style.RESET_ALL}")
        print(f"Total sites checked: {summary['total_sites']}")
        print(f"Successful checks: {summary['successful_checks']}")
        print(f"Failed checks: {summary['failed_checks']}")
        print(f"Success rate: {summary['success_rate']:.1f}%")
        print(f"Average header score: {summary['average_header_score']:.1f}")
        
        if check_ssl:
            print(f"Average SSL score: {summary['average_ssl_score']:.1f}")
        
        # Display detailed results
        print(f"\n{Fore.YELLOW}📋 Detailed Results:{Style.RESET_ALL}")
        print("-" * 80)
        
        for result in results_list:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['url']}")
            
            if result['success'] and result['headers']:
                score = result['headers']['total_score']
                percentage = (score / result['headers']['max_score']) * 100
                print(f"   Header Score: {score}/{result['headers']['max_score']} ({percentage:.1f}%)")
            
            if result['ssl']:
                ssl_score = result['ssl']['score']['total_score']
                ssl_percentage = result['ssl']['score']['percentage']
                print(f"   SSL Score: {ssl_score}/{result['ssl']['score']['max_score']} ({ssl_percentage:.1f}%)")
            
            if result.get('response') and result['response']['success']:
                resp = result['response']
                print(f"   Status: {resp['status_code']} - {resp['status_message']}")
                print(f"   Response Time: {resp['response_time']:.3f}s")
                if resp['server_info'].get('detected_type'):
                    print(f"   Server: {resp['server_info']['detected_type']}")
            
            if result['error']:
                print(f"   Error: {result['error']}")
            print()
        
        # Display top sites
        if summary['best_sites']:
            print(f"{Fore.GREEN}🏆 Top 5 Sites by Security Score:{Style.RESET_ALL}")
            for i, url in enumerate(summary['best_sites'], 1):
                print(f"  {i}. {url}")
        
        if summary['worst_sites']:
            print(f"\n{Fore.RED}⚠️ Bottom 5 Sites by Security Score:{Style.RESET_ALL}")
            for i, url in enumerate(summary['worst_sites'], 1):
                print(f"  {i}. {url}")
        
        # Save results if output file specified
        if args.output:
            print(f"\n{Fore.CYAN}💾 Saving results to {args.output}...{Style.RESET_ALL}")
            
            export_data = {
                'summary': summary,
                'results': results_list,
                'response_analysis_enabled': check_response,
                'timestamp': datetime.now().isoformat()
            }
            
            if export_results(export_data, args.output):
                print(f"{Fore.GREEN}✅ Results saved successfully!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Error: Failed to save results{Style.RESET_ALL}")
        
        return  # Exit for bulk checks
    
    # Single site check (existing logic)
    single_url = urls_to_check[0]
    
    if check_headers:
        print(f"{Fore.CYAN}🔍 Checking the security of the site: {single_url}{Style.RESET_ALL}")
        
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
            single_url,
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
        ssl_results = analyze_ssl_security(single_url, args.timeout)
    
    # Response Analysis
    response_results = None
    if check_response:
        print(f"{Fore.CYAN}📡 Analyzing HTTP response for: {single_url}{Style.RESET_ALL}")
        
        analyzer = ResponseAnalyzer()
        response_results = analyzer.analyze_response_headers(
            single_url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            verify_ssl=args.verify_ssl
        )
        
        if response_results['success']:
            print(f"\n{Fore.GREEN}📊 HTTP Response Analysis:{Style.RESET_ALL}")
            print(f"Status Code: {response_results['status_code']} - {response_results['status_message']}")
            print(f"Response Time: {response_results['response_time']:.3f} seconds")
            
            # Server information
            if response_results['server_info']:
                print(f"\n{Fore.YELLOW}🖥️ Server Information:{Style.RESET_ALL}")
                if 'server' in response_results['server_info']:
                    print(f"Server: {response_results['server_info']['server']}")
                if 'detected_type' in response_results['server_info']:
                    print(f"Detected Type: {response_results['server_info']['detected_type']}")
            
            # Security headers summary
            security_present = sum(1 for h in response_results['security_headers'].values() if h['present'])
            total_security = len(response_results['security_headers'])
            print(f"\n{Fore.CYAN}🔒 Security Headers: {security_present}/{total_security} present{Style.RESET_ALL}")
            
            # Redirect chain
            if response_results['redirect_chain']:
                print(f"\n{Fore.YELLOW}🔄 Redirect Chain:{Style.RESET_ALL}")
                for i, redirect in enumerate(response_results['redirect_chain'], 1):
                    print(f"  {i}. {redirect['url']} ({redirect['status_code']})")
            
            # Additional headers
            if response_results['additional_headers']:
                print(f"\n{Fore.BLUE}📋 Additional Headers:{Style.RESET_ALL}")
                for header, value in response_results['additional_headers'].items():
                    print(f"  {header}: {value}")
        else:
            print(f"{Fore.RED}❌ Error analyzing response: {response_results['error']}{Style.RESET_ALL}")
    
    # Print results
    if check_headers and results:
        print(f"\n{Fore.GREEN}📊 Security Header Check Results:{Style.RESET_ALL}")
        print(f"URL: {single_url}")
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
        
        if args.verbose:
            print_verbose_header_info(header_name, header_data, verbose=True)
    
    # Summary
    print(f"{Fore.CYAN}📈 Summary:{Style.RESET_ALL}")
    print(f"✅ Well configured: {results['summary']['good']}")
    print(f"❌ Issues: {results['summary']['bad']}")
    print(f"ℹ️ Info: {results['summary']['info']}")
    
    if args.verbose:
        recommendations = SecurityRecommendations()
        recommendations.print_security_summary(results, verbose=True)
        
        print(f"\n{Fore.MAGENTA}📊 Security Statistics:{Style.RESET_ALL}")
        print(f"  Total Headers Checked: {len(results['headers'])}")
        print(f"  Good Headers: {results['summary']['good']}")
        print(f"  Bad Headers: {results['summary']['bad']}")
        print(f"  Info Headers: {results['summary']['info']}")
        print(f"  Security Score: {results['total_score']}/{results['max_score']} ({(results['total_score'] / results['max_score'] * 100):.1f}%)")
        
        print(f"\n{Fore.BLUE}🏆 Best Practices Comparison:{Style.RESET_ALL}")
        print("  Industry Standard: 80%+ security score")
        print("  Excellent: 90%+ security score")
        percentage = (results['total_score'] / results['max_score']) * 100
        print("  Your Score: " + ("✅ Excellent" if percentage >= 90 else 
                                 "⚠️ Good" if percentage >= 80 else 
                                 "❌ Needs Improvement"))
    
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
            'url': single_url,
            'headers': results if check_headers else None,
            'ssl': ssl_results if check_ssl else None,
            'response': response_results if check_response else None,
            'timestamp': datetime.now().isoformat()
        }
        
        if export_results(export_data, args.output):
            print(f"{Fore.GREEN}✅ Results saved successfully!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Error: Failed to save results{Style.RESET_ALL}")

if __name__ == "__main__":
    main()