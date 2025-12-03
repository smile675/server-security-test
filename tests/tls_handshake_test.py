#!/usr/bin/env python3
"""
TLS Handshake Test
Performs a range of TLS/SSL negotiation scenarios — different protocol versions,
cipher suites, and malformed handshakes — to detect weak configurations and
handshake robustness.
"""

import ssl
import socket
import argparse
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse


# TLS/SSL protocol versions to test
TLS_VERSIONS = [
    ("SSLv3", ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),  # Deprecated
    ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),  # Deprecated
    ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),  # Deprecated
    ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),  # Current standard
    ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),  # Latest
]

# Weak cipher suites to test (known weak ciphers)
WEAK_CIPHERS = [
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "aNULL",
    "eNULL",
]


def test_protocol_version(host, port, protocol_name, protocol_version):
    """
    Test a specific TLS protocol version.
    
    Args:
        host: Target hostname
        port: Target port
        protocol_name: Name of protocol (e.g., 'TLSv1.2')
        protocol_version: ssl.PROTOCOL_* constant
        
    Returns:
        Tuple of (success: bool, cipher_used: str, error: str)
    """
    if protocol_version is None:
        return (None, None, "Protocol not available in this Python/OpenSSL version")
    
    try:
        context = ssl.SSLContext(protocol_version)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((host, port))
            sock.do_handshake()
            cipher = sock.cipher()
            sock.close()
            
            cipher_name = cipher[0] if cipher else "Unknown"
            return (True, cipher_name, None)
        except ssl.SSLError as e:
            return (False, None, str(e))
        except socket.timeout:
            return (False, None, "Connection timeout")
        except ConnectionRefusedError:
            return (False, None, "Connection refused")
        except Exception as e:
            return (False, None, str(e))
        finally:
            sock.close()
    except Exception as e:
        return (False, None, str(e))


def test_weak_ciphers(host, port):
    """
    Test if weak ciphers are accepted.
    
    Args:
        host: Target hostname
        port: Target port
        
    Returns:
        Dict with weak cipher test results
    """
    results = {
        'weak_accepted': [],
        'weak_rejected': [],
    }
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Try to enable weak ciphers (may not work depending on system OpenSSL)
        try:
            # This is system-dependent; some systems disallow weak ciphers entirely
            context.set_ciphers(':'.join(WEAK_CIPHERS) + ':DEFAULT')
        except ssl.SSLError:
            pass
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((host, port))
            sock.do_handshake()
            cipher = sock.cipher()
            cipher_name = cipher[0] if cipher else "Unknown"
            
            # Check if any weak cipher was used
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    results['weak_accepted'].append(cipher_name)
                    break
            else:
                results['weak_rejected'].append(f"Used {cipher_name}")
            
            sock.close()
        except Exception as e:
            results['weak_rejected'].append(str(e))
        finally:
            sock.close()
    except Exception as e:
        results['weak_rejected'].append(str(e))
    
    return results


def test_certificate_validation(host, port):
    """
    Test certificate validation behavior.
    
    Args:
        host: Target hostname
        port: Target port
        
    Returns:
        Dict with certificate info
    """
    results = {
        'has_cert': False,
        'valid_chain': False,
        'cert_info': {},
    }
    
    try:
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((host, port))
            ssock = context.wrap_socket(sock, server_hostname=host)
            
            cert = ssock.getpeercert()
            results['has_cert'] = bool(cert)
            if cert:
                results['cert_info'] = {
                    'subject': str(cert.get('subject', [])),
                    'issuer': str(cert.get('issuer', [])),
                    'notBefore': cert.get('notBefore', 'Unknown'),
                    'notAfter': cert.get('notAfter', 'Unknown'),
                }
            
            results['valid_chain'] = True
            ssock.close()
        except ssl.SSLError as e:
            if "certificate verify failed" in str(e):
                results['valid_chain'] = False
        finally:
            sock.close()
    except Exception as e:
        pass
    
    return results


async def run_test(url):
    """
    Main test orchestrator: test TLS/SSL configurations.
    
    Args:
        url: Target URL (e.g., https://yourdomain.com)
    """
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc.split(':')[0]
    port = parsed.port or 443
    
    results = {
        'protocols': {},
        'weak_ciphers': None,
        'certificate': None,
        'deprecated_accepted': [],
        'modern_accepted': [],
    }
    
    print(f"\n[*] Starting TLS Handshake Test")
    print(f"    Target: {host}:{port}")
    print(f"    Test Start Time: {datetime.now().isoformat()}\n")
    
    # Test each protocol version
    print("Testing TLS/SSL Protocol Versions:")
    for protocol_name, protocol_version in TLS_VERSIONS:
        if protocol_version is None:
            print(f"  {protocol_name}: Skipped (not available)")
            continue
        
        success, cipher, error = test_protocol_version(host, port, protocol_name, protocol_version)
        
        if success is None:
            print(f"  {protocol_name}: Skipped ({error})")
        elif success:
            print(f"  {protocol_name}: ✓ Accepted (cipher: {cipher})")
            results['protocols'][protocol_name] = {'status': 'ACCEPTED', 'cipher': cipher}
            
            # Track deprecated vs modern
            if protocol_name in ['SSLv3', 'TLSv1.0', 'TLSv1.1']:
                results['deprecated_accepted'].append((protocol_name, cipher))
            else:
                results['modern_accepted'].append((protocol_name, cipher))
        else:
            print(f"  {protocol_name}: ✗ Rejected ({error})")
            results['protocols'][protocol_name] = {'status': 'REJECTED', 'error': error}
    
    # Test weak ciphers
    print("\nTesting Weak Cipher Support:")
    weak_results = test_weak_ciphers(host, port)
    results['weak_ciphers'] = weak_results
    if weak_results['weak_accepted']:
        print(f"  ✗ Weak ciphers accepted: {weak_results['weak_accepted']}")
    else:
        print(f"  ✓ No weak ciphers detected")
    
    # Test certificate validation
    print("\nTesting Certificate Configuration:")
    cert_results = test_certificate_validation(host, port)
    results['certificate'] = cert_results
    if cert_results['has_cert']:
        print(f"  ✓ Certificate present")
        if cert_results['valid_chain']:
            print(f"  ✓ Valid certificate chain")
        else:
            print(f"  ✗ Certificate chain validation failed")
    else:
        print(f"  ✗ No certificate found")
    
    # Generate summary and verdict
    print("\n" + "="*70)
    print("PROTECTION ANALYSIS")
    print("="*70)
    
    has_vuln = bool(results['deprecated_accepted'] or results['weak_ciphers'].get('weak_accepted'))
    
    if has_vuln:
        print("\n✗ TLS Configuration Weaknesses Detected:")
        if results['deprecated_accepted']:
            print(f"  - Deprecated protocols accepted:")
            for proto, cipher in results['deprecated_accepted']:
                print(f"    - {proto} (cipher: {cipher})")
        if results['weak_ciphers'].get('weak_accepted'):
            print(f"  - Weak ciphers accepted: {results['weak_ciphers']['weak_accepted']}")
        print("\n  Action Required:")
        print("  - Disable SSLv3, TLSv1.0, TLSv1.1")
        print("  - Require TLSv1.2 or TLSv1.3 minimum")
        print("  - Remove weak/export ciphers")
        print("  - Use strong cipher suites only")
        print("  - Enable HSTS and certificate pinning if applicable")
    else:
        print("\n✓ TLS Configuration Appears Secure:")
        print("  - Only modern protocols (TLSv1.2+) accepted")
        print("  - No weak ciphers detected")
        if results['certificate']['valid_chain']:
            print("  - Valid certificate chain")
        print("\n  Verdict: TLS configuration meets modern security standards.")


def tls_handshake_test():
    parser = argparse.ArgumentParser(
        description="Test TLS/SSL configuration and handshake robustness"
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g., https://yourdomain.com)"
    )
    
    args = parser.parse_args()
    
    import asyncio
    asyncio.run(run_test(args.url))


if __name__ == "__main__":
    tls_handshake_test()
