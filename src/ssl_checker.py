"""Certificate validation and conservative TLS probes.

A failed local probe is UNKNOWN unless the peer explicitly rejects the version.
The cipher check inspects only the negotiated suite, not all server suites.
"""
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit
from typing import Dict, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID

SSL_SECURITY_CONFIG = {
    'tls_versions': {
        'TLS 1.3': {'score': 20, 'secure': True},
        'TLS 1.2': {'score': 15, 'secure': True},
        'TLS 1.1': {'score': 5, 'secure': False},
        'TLS 1.0': {'score': 0, 'secure': False},
        'SSL 3.0': {'score': 0, 'secure': False},
        'SSL 2.0': {'score': 0, 'secure': False}
    },
    'certificate_checks': {
        'valid_certificate': {'score': 25, 'description': 'Certificate is valid'},
        'not_expired': {'score': 15, 'description': 'Certificate is not expired'},
        'strong_algorithm': {'score': 10, 'description': 'Strong cryptographic algorithm'},
    },
    'cipher_suites': {
        'strong': {'score': 10, 'description': 'Strong cipher suites available'},
        'medium': {'score': 5, 'description': 'Medium strength cipher suites'},
        'weak': {'score': 0, 'description': 'Weak cipher suites detected'}
    }
}

def get_hostname_and_port(url: str) -> Tuple[str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'Invalid HTTP(S) URL: {url}')
    # This module probes TLS; HTTP input without a port targets HTTPS port 443.
    return parsed.hostname, parsed.port or 443


def _read_der(hostname, port, timeout, context):
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as connection:
            return connection.getpeercert(binary_form=True)


def _dns_matches(pattern, hostname):
    pattern = pattern.lower().rstrip('.')
    hostname = hostname.encode('idna').decode('ascii').lower().rstrip('.')
    if '*' not in pattern:
        return pattern == hostname
    return (pattern.startswith('*.') and pattern.count('*') == 1
            and len(pattern.split('.')) == len(hostname.split('.'))
            and pattern.split('.')[1:] == hostname.split('.')[1:])


def _certificate_details(der, hostname):
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ips = san.get_values_for_type(x509.IPAddress)
    except x509.ExtensionNotFound:
        dns_names, ips = [], []
    try:
        address = ipaddress.ip_address(hostname)
        hostname_valid = address in ips
    except ValueError:
        hostname_valid = any(_dns_matches(name, hostname) for name in dns_names)
        # Match OpenSSL's common-name fallback only when no DNS SAN is present.
        if not dns_names:
            hostname_valid = any(_dns_matches(attr.value, hostname)
                                 for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    algorithm = cert.signature_hash_algorithm
    return {
        'subject': {attr.oid._name: attr.value for attr in cert.subject},
        'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
        'not_before': cert.not_valid_before_utc.isoformat(),
        'not_after': cert.not_valid_after_utc.isoformat(),
        'is_expired': now > cert.not_valid_after_utc,
        'not_yet_valid': now < cert.not_valid_before_utc,
        'hostname_valid': hostname_valid,
        'san_list': dns_names + [str(ip) for ip in ips],
        'signature_algorithm': algorithm.name if algorithm else cert.signature_algorithm_oid._name,
        'version': cert.version.name,
    }


def check_ssl_certificate(url: str, timeout: int = 10) -> Dict:
    verification_error = None
    verification_code = None
    try:
        hostname, port = get_hostname_and_port(url)
        try:
            der = _read_der(hostname, port, timeout, ssl.create_default_context())
        except ssl.SSLCertVerificationError as exc:
            verification_error = str(exc)
            verification_code = exc.verify_code
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # This second connection only retrieves details; it never grants trust.
            der = _read_der(hostname, port, timeout, context)
        details = _certificate_details(der, hostname)
        details.update(success=verification_error is None, parsed=True,
                       verified=verification_error is None,
                       verification_error=verification_error,
                       verification_code=verification_code,
                       error=verification_error)
        return details
    except Exception as exc:
        return {'success': False, 'parsed': False, 'verified': False,
                'verification_error': verification_error,
                'verification_code': verification_code,
                'error': f'{type(exc).__name__}: {exc}'}


def check_tls_protocols(url: str, timeout: int = 10) -> Dict:
    try:
        hostname, port = get_hostname_and_port(url)
    except ValueError as exc:
        return {'success': False, 'complete': False, 'protocols': {}, 'error': str(exc)}
    protocols = {}
    for version, name in ((ssl.TLSVersion.TLSv1_3, 'TLS 1.3'),
                          (ssl.TLSVersion.TLSv1_2, 'TLS 1.2'),
                          (ssl.TLSVersion.TLSv1_1, 'TLS 1.1'),
                          (ssl.TLSVersion.TLSv1, 'TLS 1.0')):
        info = {'supported': None, 'status': 'UNKNOWN', 'version': None,
                'cipher': None, 'error': None}
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as connection:
                    info.update(supported=True, status='SUPPORTED',
                                version=connection.version(), cipher=connection.cipher()[0])
        except ssl.SSLError as exc:
            # Generic handshake failures can be caused by client cipher policy.
            if exc.reason == 'TLSV1_ALERT_PROTOCOL_VERSION':
                info.update(supported=False, status='UNSUPPORTED')
            info['error'] = f'{type(exc).__name__}: {exc}'
        except (OSError, ValueError) as exc:
            info['error'] = f'{type(exc).__name__}: {exc}'
        protocols[name] = info
    complete = all(info['supported'] is not None for info in protocols.values())
    errors = '; '.join(f"{name}: {info['error']}" for name, info in protocols.items()
                       if info['supported'] is None)
    return {'success': complete, 'complete': complete, 'protocols': protocols,
            'error': errors or None}


def check_cipher_suites(url: str, timeout: int = 10) -> Dict:
    try:
        hostname, port = get_hostname_and_port(url)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as connection:
                cipher = connection.cipher()
        name = cipher[0].upper().replace('-', '_')
        # Classify only a clearly recognised negotiated suite.
        if ('GCM' in name and 'AES' in name) or 'CHACHA20' in name:
            category = 'strong'
        elif 'AES' in name:
            category = 'medium'
        else:
            category = 'weak'
        return {'success': True, 'current_cipher': cipher[0],
                'cipher_version': cipher[1], 'cipher_bits': cipher[2],
                'strong_ciphers': [cipher[0]] if category == 'strong' else [],
                'medium_ciphers': [cipher[0]] if category == 'medium' else [],
                'weak_ciphers': [cipher[0]] if category == 'weak' else [],
                'scope': 'negotiated_suite_only'}
    except Exception as exc:
        return {'success': False, 'error': f'{type(exc).__name__}: {exc}'}


def calculate_ssl_score(cert_info: Dict, protocols_info: Dict, ciphers_info: Dict) -> Dict:
    config = SSL_SECURITY_CONFIG
    max_score = (sum(item['score'] for item in config['certificate_checks'].values())
                 + sum(item['score'] for item in config['tls_versions'].values() if item['secure'])
                 + config['cipher_suites']['strong']['score'])
    score = 0
    details = []
    if cert_info.get('parsed') or cert_info.get('success'):
        checks = {
            'valid_certificate': cert_info.get('verified', False) and cert_info.get('hostname_valid', False),
            'not_expired': not cert_info.get('is_expired', True) and not cert_info.get('not_yet_valid', False),
            'strong_algorithm': cert_info.get('signature_algorithm', '').lower() in
                                ('sha256', 'sha384', 'sha512', 'ed25519', 'ed448'),
        }
        for name, passed in checks.items():
            if passed:
                score += config['certificate_checks'][name]['score']
            details.append(f"{'PASS' if passed else 'FAIL'}: {name}")
    else:
        details.append('UNKNOWN: certificate details unavailable')
    protocols = protocols_info.get('protocols', {})
    for name, info in protocols.items():
        supported = info['supported']
        if supported is None:
            details.append(f'UNKNOWN: {name} could not be checked')
        elif supported:
            if config['tls_versions'][name]['secure']:
                score += config['tls_versions'][name]['score']
                details.append(f'PASS: {name} supported')
            else:
                details.append(f'FAIL: {name} insecure protocol supported')
        else:
            details.append(f"{'FAIL' if config['tls_versions'][name]['secure'] else 'PASS'}: {name} not supported")
    if ciphers_info.get('success'):
        if ciphers_info.get('strong_ciphers'):
            score += config['cipher_suites']['strong']['score']
        elif ciphers_info.get('medium_ciphers'):
            score += config['cipher_suites']['medium']['score']
    complete = (bool(cert_info.get('parsed') or cert_info.get('success'))
                and protocols_info.get('complete', protocols_info.get('success', False))
                and ciphers_info.get('success', False))
    percentage = round(score / max_score * 100, 1)
    if not complete:
        level, emoji = 'Incomplete', '⚪'
    elif percentage >= 80:
        level, emoji = 'Excellent', '🟢'
    elif percentage >= 60:
        level, emoji = 'Good', '🟡'
    elif percentage >= 40:
        level, emoji = 'Fair', '🟠'
    else:
        level, emoji = 'Poor', '🔴'
    return {'total_score': score, 'max_score': max_score, 'percentage': percentage,
            'security_level': level, 'level_emoji': emoji, 'details': details,
            'complete': bool(complete),
            'limitations': 'Project heuristic, not a security standard. Unknown probes earn no points; only the negotiated cipher is inspected.'}


def analyze_ssl_security(url: str, timeout: int = 10) -> Dict:
    cert = check_ssl_certificate(url, timeout)
    protocols = check_tls_protocols(url, timeout)
    ciphers = check_cipher_suites(url, timeout)
    errors = {name: value.get('error') or 'Analysis incomplete'
              for name, value in [('certificate', cert), ('protocols', protocols), ('ciphers', ciphers)]
              if not value.get('success')}
    return {'success': not errors, 'url': url, 'certificate': cert,
            'protocols': protocols, 'ciphers': ciphers,
            'score': calculate_ssl_score(cert, protocols, ciphers),
            'errors': errors,
            'error': '; '.join(f'{name}: {error}' for name, error in errors.items()) or None}
