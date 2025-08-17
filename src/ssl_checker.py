"""
Module for SSL/TLS security analysis
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style

# SSL/TLS Security Configuration
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
        'proper_issuer': {'score': 5, 'description': 'Certificate from trusted CA'},
        'san_present': {'score': 5, 'description': 'Subject Alternative Names present'}
    },
    'cipher_suites': {
        'strong': {'score': 10, 'description': 'Strong cipher suites available'},
        'medium': {'score': 5, 'description': 'Medium strength cipher suites'},
        'weak': {'score': 0, 'description': 'Weak cipher suites detected'}
    }
}

def get_hostname_and_port(url: str) -> Tuple[str, int]:
    """
    Extract hostname and port from URL
    
    Args:
        url (str): URL to parse
        
    Returns:
        Tuple[str, int]: (hostname, port)
    """
    # Remove protocol
    if url.startswith('https://'):
        url = url[8:]
    elif url.startswith('http://'):
        url = url[7:]
    
    # Split hostname and port
    if ':' in url:
        hostname, port_str = url.split(':', 1)
        if '/' in port_str:
            port_str = port_str.split('/', 1)[0]
        port = int(port_str)
    else:
        hostname = url.split('/', 1)[0]
        port = 443
    
    return hostname, port

def check_ssl_certificate(url: str, timeout: int = 10) -> Dict:
    """
    Check SSL certificate information
    
    Args:
        url (str): URL to check
        timeout (int): Connection timeout
        
    Returns:
        Dict: Certificate information
    """
    try:
        hostname, port = get_hostname_and_port(url)
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate information
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                # Check expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                is_expired = datetime.now() > not_after
                
                # Check if certificate is valid for hostname
                san_list = []
                if 'subjectAltName' in cert:
                    for type_name, value in cert['subjectAltName']:
                        if type_name == 'DNS':
                            san_list.append(value)
                
                # Check if hostname matches
                hostname_valid = (
                    hostname in san_list or 
                    subject.get('commonName', '') == hostname
                )
                
                return {
                    'success': True,
                    'subject': subject,
                    'issuer': issuer,
                    'not_after': not_after.isoformat(),
                    'is_expired': is_expired,
                    'hostname_valid': hostname_valid,
                    'san_list': san_list,
                    'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                    'version': cert.get('version', 'Unknown')
                }
                
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def check_tls_protocols(url: str, timeout: int = 10) -> Dict:
    """
    Check supported TLS protocols
    
    Args:
        url (str): URL to check
        timeout (int): Connection timeout
        
    Returns:
        Dict: Supported protocols information
    """
    hostname, port = get_hostname_and_port(url)
    supported_protocols = {}
    
    # Test different TLS versions
    tls_versions = [
        (ssl.TLSVersion.TLSv1_3, 'TLS 1.3'),
        (ssl.TLSVersion.TLSv1_2, 'TLS 1.2'),
        (ssl.TLSVersion.TLSv1_1, 'TLS 1.1'),
        (ssl.TLSVersion.TLSv1, 'TLS 1.0')
    ]
    
    for tls_version, version_name in tls_versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = tls_version
            context.maximum_version = tls_version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported_protocols[version_name] = {
                        'supported': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0]
                    }
        except Exception:
            supported_protocols[version_name] = {
                'supported': False,
                'version': None,
                'cipher': None
            }
    
    return {
        'success': True,
        'protocols': supported_protocols
    }

def check_cipher_suites(url: str, timeout: int = 10) -> Dict:
    """
    Check available cipher suites
    
    Args:
        url (str): URL to check
        timeout (int): Connection timeout
        
    Returns:
        Dict: Cipher suites information
    """
    try:
        hostname, port = get_hostname_and_port(url)
        
        # Get all available cipher suites
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                
                # Categorize cipher suites by strength
                strong_ciphers = []
                medium_ciphers = []
                weak_ciphers = []
                
                # Simple categorization based on cipher name
                cipher_name = cipher[0].lower()
                
                if any(strong in cipher_name for strong in ['aes_256', 'chacha20', 'aes_128_gcm']):
                    strong_ciphers.append(cipher[0])
                elif any(medium in cipher_name for medium in ['aes_128', '3des']):
                    medium_ciphers.append(cipher[0])
                else:
                    weak_ciphers.append(cipher[0])
                
                return {
                    'success': True,
                    'current_cipher': cipher[0],
                    'cipher_version': cipher[1],
                    'cipher_bits': cipher[2],
                    'strong_ciphers': strong_ciphers,
                    'medium_ciphers': medium_ciphers,
                    'weak_ciphers': weak_ciphers
                }
                
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def calculate_ssl_score(cert_info: Dict, protocols_info: Dict, ciphers_info: Dict) -> Dict:
    """
    Calculate SSL/TLS security score
    
    Args:
        cert_info (Dict): Certificate information
        protocols_info (Dict): Protocols information
        ciphers_info (Dict): Cipher suites information
        
    Returns:
        Dict: Security score and details
    """
    total_score = 0
    max_score = 100
    details = []
    
    # Certificate checks
    if cert_info.get('success'):
        if not cert_info.get('is_expired'):
            total_score += SSL_SECURITY_CONFIG['certificate_checks']['not_expired']['score']
            details.append(f"✅ {SSL_SECURITY_CONFIG['certificate_checks']['not_expired']['description']}")
        else:
            details.append(f"❌ Certificate is expired")
        
        if cert_info.get('hostname_valid'):
            total_score += SSL_SECURITY_CONFIG['certificate_checks']['valid_certificate']['score']
            details.append(f"✅ {SSL_SECURITY_CONFIG['certificate_checks']['valid_certificate']['description']}")
        else:
            details.append(f"❌ Certificate hostname mismatch")
        
        if 'sha256' in cert_info.get('signature_algorithm', '').lower():
            total_score += SSL_SECURITY_CONFIG['certificate_checks']['strong_algorithm']['score']
            details.append(f"✅ {SSL_SECURITY_CONFIG['certificate_checks']['strong_algorithm']['description']}")
        else:
            details.append(f"⚠️ Weak signature algorithm")
    
    # Protocol checks
    if protocols_info.get('success'):
        protocols = protocols_info.get('protocols', {})
        
        for protocol_name, config in SSL_SECURITY_CONFIG['tls_versions'].items():
            if protocol_name in protocols:
                if protocols[protocol_name]['supported']:
                    if config['secure']:
                        total_score += config['score']
                        details.append(f"✅ {protocol_name}: Supported")
                    else:
                        details.append(f"❌ {protocol_name}: Supported (insecure)")
                else:
                    if config['secure']:
                        details.append(f"❌ {protocol_name}: Not supported")
                    else:
                        details.append(f"✅ {protocol_name}: Not supported (good)")
    
    # Cipher checks
    if ciphers_info.get('success'):
        if ciphers_info.get('strong_ciphers'):
            total_score += SSL_SECURITY_CONFIG['cipher_suites']['strong']['score']
            details.append(f"✅ {SSL_SECURITY_CONFIG['cipher_suites']['strong']['description']}")
        elif ciphers_info.get('medium_ciphers'):
            total_score += SSL_SECURITY_CONFIG['cipher_suites']['medium']['score']
            details.append(f"⚠️ {SSL_SECURITY_CONFIG['cipher_suites']['medium']['description']}")
        else:
            details.append(f"❌ {SSL_SECURITY_CONFIG['cipher_suites']['weak']['description']}")
    
    # Determine security level
    if total_score >= 80:
        security_level = "Excellent"
        level_emoji = "🟢"
    elif total_score >= 60:
        security_level = "Good"
        level_emoji = "🟡"
    elif total_score >= 40:
        security_level = "Fair"
        level_emoji = "🟠"
    else:
        security_level = "Poor"
        level_emoji = "🔴"
    
    return {
        'total_score': total_score,
        'max_score': max_score,
        'percentage': round((total_score / max_score) * 100, 1),
        'security_level': security_level,
        'level_emoji': level_emoji,
        'details': details
    }

def analyze_ssl_security(url: str, timeout: int = 10) -> Dict:
    """
    Complete SSL/TLS security analysis
    
    Args:
        url (str): URL to analyze
        timeout (int): Connection timeout
        
    Returns:
        Dict: Complete SSL/TLS analysis results
    """
    print(f"{Fore.CYAN}🔒 Analyzing SSL/TLS security for: {url}{Style.RESET_ALL}")
    
    # Perform all checks
    cert_info = check_ssl_certificate(url, timeout)
    protocols_info = check_tls_protocols(url, timeout)
    ciphers_info = check_cipher_suites(url, timeout)
    
    # Calculate score
    score_info = calculate_ssl_score(cert_info, protocols_info, ciphers_info)
    
    return {
        'success': True,
        'url': url,
        'certificate': cert_info,
        'protocols': protocols_info,
        'ciphers': ciphers_info,
        'score': score_info
    }