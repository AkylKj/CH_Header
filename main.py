#!/usr/bin/env python3
"""Command-line entrypoint for Security Header Checker."""
import argparse
import sys
from colorama import Fore, Style, init
from src.bulk_checker import BulkChecker, validate_url
from src.exporter import export_results
from src.header_checker import print_verbose_header_info
from src.recommendations import SecurityRecommendations

VERSION = '0.0.6'
LIMITATIONS = ('Scores are project heuristics, not a security standard or a full audit. '
               'CSP/HSTS/cookies, framing, CORS, caching and data clearing use structured rules; combined CSP scoring is excluded. Legacy headers and contextual CORS/cache/clearing checks earn no points. Other headers still use basic matching.')


def positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Expected a positive integer') from exc
    if number <= 0:
        raise argparse.ArgumentTypeError('Expected a positive integer')
    return number


def build_parser():
    parser = argparse.ArgumentParser(description='Security Header Checker',
        epilog='Example: python main.py https://example.com --ssl-check --output report.json')
    parser.add_argument('url', nargs='?', help='HTTP(S) URL to check')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--output', '-o', help='Report path (.txt, .json, .csv)')
    parser.add_argument('--timeout', '-t', type=positive_int, default=10)
    parser.add_argument('--user-agent', '-U', default=f'Security-Header-Checker/{VERSION}')
    parser.add_argument('--version', '-V', action='version', version=f'%(prog)s {VERSION}')
    redirects = parser.add_mutually_exclusive_group()
    redirects.add_argument('--follow-redirects', '-F', action='store_true')
    redirects.add_argument('--no-redirects', '-n', action='store_true')
    parser.add_argument('--max-redirects', type=positive_int, default=5)
    verification = parser.add_mutually_exclusive_group()
    verification.add_argument('--verify-ssl', action='store_true', default=True)
    verification.add_argument('--no-verify-ssl', action='store_true')
    parser.add_argument('--ssl-check', action='store_true')
    parser.add_argument('--response-analysis', action='store_true')
    only = parser.add_mutually_exclusive_group()
    only.add_argument('--ssl-only', action='store_true')
    only.add_argument('--response-only', action='store_true')
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument('--file', '-f', help='UTF-8 file with one URL per line')
    inputs.add_argument('--urls', '-u', help='Comma-separated URLs')
    parser.add_argument('--parallel', '-p', type=positive_int, default=1)
    parser.add_argument('--batch-size', '-b', type=positive_int, default=10)
    return parser


def print_site(result, verbose=False):
    print(f"\nURL: {result['url']}")
    headers = result.get('headers')
    if headers is not None:
        print('Security Header Check Results:')
        if headers.get('success'):
            if headers['max_score']:
                print(f"Total Score: {headers['total_score']}/{headers['max_score']} ({headers.get('percentage')}%)")
            else:
                print('Total Score: N/A (no applicable checks)')
            print(f"Final URL: {headers.get('final_url', result['url'])}")
            for name, detail in headers['headers'].items():
                color = Fore.GREEN if detail['status'] == 'GOOD' else Fore.YELLOW if detail['status'] == 'WARNING' else Fore.CYAN if detail['status'] == 'INFO' else Fore.RED
                print(f"  {name}: {detail['value']} [{color}{detail['status']}{Style.RESET_ALL}] ({detail['score']})")
                for item in detail.get('findings', []):
                    print(f"    [{item['status']}] {item['message']}")
                    if item.get('recommendation'):
                        print(f"      Recommendation: {item['recommendation']}")
                if verbose:
                    print_verbose_header_info(name, detail, verbose=True)
            print('Summary: ' + ', '.join(f'{key}: {value}' for key, value in headers['summary'].items()))
            if verbose:
                SecurityRecommendations().print_security_summary(headers, verbose=True)
    response = result.get('response')
    if response is not None:
        print('HTTP Response Analysis:')
        if response.get('success'):
            print(f"Final URL: {response['final_url']}")
            print(f"Status Code: {response['status_code']} - {response['status_message']}")
            print(f"Response Time: {response['response_time']:.3f}s")
            print(f"Server Information: {response['server_info']}")
            for redirect in response['redirect_chain']:
                print(f"  Redirect: {redirect['url']} ({redirect['status_code']})")
            if verbose:
                for name, detail in response['security_headers'].items():
                    print(f"  {name}: {detail['value']}")
                for name, value in response['additional_headers'].items():
                    print(f'  {name}: {value}')
    tls = result.get('ssl')
    if tls is not None:
        print('SSL/TLS Security Results:')
        if tls.get('score'):
            score = tls['score']
            print(f"SSL Score: {score['total_score']}/{score['max_score']} ({score['percentage']}%)")
            print(f"Security Level: {score['security_level']}")
            print(score['limitations'])
        cert = tls.get('certificate', {})
        if cert.get('parsed'):
            print(f"Certificate Subject: {cert['subject']}")
            print(f"Issuer: {cert['issuer']} | Expires: {cert['not_after']}")
            print(f"Verified: {cert['verified']} | Hostname Match: {cert['hostname_valid']} | Expired: {cert['is_expired']}")
        for name, info in tls.get('protocols', {}).get('protocols', {}).items():
            print(f"  {name}: {info['status']}")
            if info.get('error'):
                print(f"    {info['error']}")
        cipher = tls.get('ciphers', {})
        if cipher.get('success'):
            print(f"Negotiated Cipher: {cipher['current_cipher']} ({cipher['cipher_bits']} bits)")
    for module, error in result.get('errors', {}).items():
        print(f'{Fore.RED}Error ({module}): {error}{Style.RESET_ALL}')


def main(argv=None):
    init(autoreset=True)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.url and (args.file or args.urls):
        parser.error('Provide only one URL source: positional URL, --file or --urls')
    checker = BulkChecker(args.parallel, args.batch_size)
    try:
        if args.file:
            urls = checker.load_urls_from_file(args.file)
        elif args.urls:
            urls = checker.parse_urls_string(args.urls)
        elif args.url:
            urls = [validate_url(args.url)]
        else:
            parser.error('Provide a URL, --file or --urls')
        if not urls:
            parser.error('No URLs provided')
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    check_headers = not (args.ssl_only or args.response_only)
    check_ssl = args.ssl_only or (args.ssl_check and not args.response_only)
    check_response = args.response_only or (args.response_analysis and not args.ssl_only)
    if args.verbose:
        print(f'Timeout: {args.timeout}s | Parallel: {args.parallel} | Batch size: {args.batch_size}')
        print(f'Follow redirects: {args.follow_redirects and not args.no_redirects} | Max redirects: {args.max_redirects}')
        print(f'Verify HTTP certificates: {not args.no_verify_ssl}')
    results = checker.check_multiple_sites(urls, check_ssl=check_ssl,
        check_headers=check_headers, check_response=check_response,
        timeout=args.timeout, user_agent=args.user_agent,
        follow_redirects=args.follow_redirects and not args.no_redirects,
        max_redirects=args.max_redirects, verify_ssl=not args.no_verify_ssl)
    for result in results:
        print_site(result, args.verbose)
    print(LIMITATIONS)
    if len(results) > 1:
        summary = checker.generate_summary_report(results)
        print('\nBulk Check Summary:')
        for name in ('total_sites', 'successful_checks', 'failed_checks', 'success_rate'):
            print(f'{name}: {summary[name]}')
        if check_headers:
            average = summary['average_header_score']
            print(f"Average absolute header score: {average:.1f}" if average is not None else 'Average absolute header score: N/A')
            percentage = summary['average_header_percentage']
            print(f"Average header percentage: {percentage:.1f}%" if percentage is not None else 'Average header percentage: N/A')
            print(f"Best sites: {summary['best_sites']}")
            print(f"Worst sites: {summary['worst_sites']}")
        if check_ssl:
            print(f"Average SSL score: {summary['average_ssl_score']:.1f}")
        report = {'summary': summary, 'results': results,
                  'response_analysis_enabled': check_response,
                  'timestamp': results[-1]['timestamp']}
    else:
        report = results[0]
    exported = True
    if args.output:
        exported = export_results(report, args.output)
        print('Results saved successfully' if exported else 'Error: Failed to save results')
    return 0 if exported and all(result['success'] for result in results) else 1


if __name__ == '__main__':
    sys.exit(main())
