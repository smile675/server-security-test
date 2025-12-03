#!/usr/bin/env python3
"""
Directory Traversal Test
Issues specially crafted path requests (e.g., '../', encoded traversal sequences)
and requests for known sensitive files to check for filesystem access leaks or
incorrect path normalization. Verifies server and application-layer path sanitization.
"""

import asyncio
import argparse
import aiohttp
import time
from collections import defaultdict
from datetime import datetime


# Directory traversal payloads and sensitive file patterns
TRAVERSAL_PAYLOADS = [
    # Basic traversal attempts
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    
    # URL-encoded traversal
    "%2e%2e%2f",
    "%2e%2e%2f%2e%2e%2f",
    "..%2f",
    "..%252f",
    
    # Double-encoded
    "%252e%252e%252f",
    
    # Backslash variants (Windows)
    "..\\",
    "..\\..\\",
    
    # URL encoded backslash
    "%5c",
    "%5c%5c",
    
    # Null byte injection
    "../null%00.txt",
    "..%00/",
    
    # Unicode/UTF-8 encoding
    "..%c0%af",
    "..%e0%80%af",
]

SENSITIVE_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "proc/self/environ",
    "var/www/html/index.php",
    "Windows/System32/drivers/etc/hosts",
    "boot.ini",
    ".env",
    ".git/config",
    ".htaccess",
    "web.config",
    "config.php",
    "database.yml",
    "secrets.json",
]


def payload_generator():
    """Generate directory traversal payloads and sensitive file requests."""
    idx = 0
    all_payloads = TRAVERSAL_PAYLOADS + SENSITIVE_FILES
    while True:
        payload = all_payloads[idx % len(all_payloads)]
        idx += 1
        yield payload


async def worker(session, base_url, concurrency_id, max_attempts, results):
    """
    Worker coroutine that sends directory traversal requests.
    
    Args:
        session: aiohttp ClientSession
        base_url: Base URL to append payloads to
        concurrency_id: Worker identifier
        max_attempts: Maximum requests per worker
        results: Shared dict to collect metrics
    """
    gen = payload_generator()
    
    for attempt_num in range(max_attempts):
        try:
            payload = next(gen)
            test_url = base_url.rstrip('/') + '/' + payload
            
            start_time = time.time()
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    elapsed = time.time() - start_time
                    status = resp.status
                    body = await resp.text()
                    
                    results['total_requests'] += 1
                    results['status_codes'][status] += 1
                    results['latencies'].append(elapsed)
                    
                    # Track successful traversal (200 with payload in URL)
                    if status == 200 and len(body) > 0:
                        results['successful_access'] += 1
                        results['traversal_samples'].append((payload, status, len(body)))
                        
                        # Check for sensitive file content indicators
                        sensitive_indicators = [
                            ('root:', 'Unix passwd file'),
                            ('root:x:', 'Unix shadow-like file'),
                            ('127.0.0.1', 'hosts file'),
                            ('PATHEXT=', 'Windows environment'),
                            ('SYSTEMROOT=', 'Windows environment'),
                            ('<?php', 'PHP source'),
                            ('<?', 'Server-side code'),
                            ('BEGIN', 'Key or certificate'),
                            ('password', 'Credentials/config'),
                            ('apikey', 'API key exposure'),
                            ('secret', 'Secret exposure'),
                        ]
                        
                        for indicator, file_type in sensitive_indicators:
                            if indicator.lower() in body.lower():
                                results['sensitive_content_leaked'] += 1
                                results['leak_samples'].append((payload, file_type))
                                break
                    
                    # Track forbidden/blocked attempts (good defense)
                    if status == 403:
                        results['blocked_attempts'] += 1
                    
                    # Track not found (good defense if traversal was attempted)
                    if status == 404 and any(x in payload for x in ['..', '%2e', '%5c']):
                        results['sanitized_attempts'] += 1
                    
            except asyncio.TimeoutError:
                results['total_requests'] += 1
                results['timeouts'] += 1
            except aiohttp.ClientConnectionError:
                results['total_requests'] += 1
                results['connection_errors'] += 1
            except Exception as e:
                results['total_requests'] += 1
                results['other_errors'] += 1
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        except Exception as e:
            results['other_errors'] += 1


async def run_test(url, base_path, concurrency, duration):
    """
    Main test orchestrator: run concurrent workers for specified duration.
    
    Args:
        url: Target URL (e.g., https://yourdomain.com)
        base_path: Base path to append traversal payloads to (e.g., '/api/file')
        concurrency: Number of parallel workers
        duration: Test duration in seconds
    """
    results = {
        'total_requests': 0,
        'status_codes': defaultdict(int),
        'latencies': [],
        'timeouts': 0,
        'connection_errors': 0,
        'other_errors': 0,
        'successful_access': 0,
        'traversal_samples': [],
        'sensitive_content_leaked': 0,
        'leak_samples': [],
        'blocked_attempts': 0,
        'sanitized_attempts': 0,
    }
    
    print(f"\n[*] Starting Directory Traversal Test")
    print(f"    Target: {url}{base_path}")
    print(f"    Concurrency: {concurrency}")
    print(f"    Duration: {duration}s")
    print(f"    Test Start Time: {datetime.now().isoformat()}\n")
    
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        
        # Start workers
        workers = [
            worker(session, url.rstrip('/') + base_path, i, 1000, results)
            for i in range(concurrency)
        ]
        
        # Run for specified duration, then cancel tasks
        try:
            await asyncio.sleep(duration)
        finally:
            for task in asyncio.all_tasks():
                if task != asyncio.current_task():
                    task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
    
    elapsed = time.time() - start_time
    
    # Generate summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Requests: {results['total_requests']}")
    print(f"Elapsed Time: {elapsed:.2f}s")
    print(f"Requests/sec: {results['total_requests'] / elapsed:.2f}" if elapsed > 0 else "N/A")
    
    print("\nStatus Code Distribution:")
    for status in sorted(results['status_codes'].keys()):
        count = results['status_codes'][status]
        print(f"  HTTP {status}: {count}")
    
    print(f"\nError Summary:")
    print(f"  Timeouts: {results['timeouts']}")
    print(f"  Connection Errors: {results['connection_errors']}")
    print(f"  Other Errors: {results['other_errors']}")
    
    if results['latencies']:
        latencies = sorted(results['latencies'])
        print(f"\nLatency Statistics:")
        print(f"  Min: {min(latencies):.3f}s")
        print(f"  Max: {max(latencies):.3f}s")
        print(f"  Avg: {sum(latencies) / len(latencies):.3f}s")
        print(f"  Median: {latencies[len(latencies)//2]:.3f}s")
    
    print(f"\nDirectory Traversal Indicators:")
    print(f"  Successful Access (HTTP 200): {results['successful_access']}")
    if results['traversal_samples']:
        print(f"    Samples:")
        for payload, status, body_len in results['traversal_samples'][:5]:
            print(f"      {payload} → {status} ({body_len} bytes)")
    
    print(f"  Sensitive Content Leaked: {results['sensitive_content_leaked']}")
    if results['leak_samples']:
        print(f"    Samples:")
        for payload, file_type in results['leak_samples'][:5]:
            print(f"      {payload} → {file_type}")
    
    print(f"  Blocked/Forbidden (HTTP 403): {results['blocked_attempts']}")
    print(f"  Sanitized (404 on traversal): {results['sanitized_attempts']}")
    
    # Protection verdict
    print("\n" + "="*70)
    print("PROTECTION ANALYSIS")
    print("="*70)
    
    has_vuln = (
        results['successful_access'] > 0 or
        results['sensitive_content_leaked'] > 0
    )
    has_defense = (
        results['blocked_attempts'] > results['successful_access'] or
        results['sanitized_attempts'] > 0
    )
    
    if has_vuln:
        print("\n✗ CRITICAL: Potential directory traversal vulnerability detected!")
        print(f"  - {results['successful_access']} successful traversal attempts (HTTP 200)")
        if results['sensitive_content_leaked'] > 0:
            print(f"  - {results['sensitive_content_leaked']} requests exposed sensitive content")
            print("  - Sensitive files or credentials may be accessible")
        print("\n  Action Required:")
        print("  - Implement strict path normalization and validation")
        print("  - Sanitize user-supplied paths before file access")
        print("  - Disable directory listing and file enumeration")
        print("  - Use a whitelist of allowed paths/files")
        print("  - Deploy WAF rules to block traversal patterns")
    elif has_defense:
        print("\n✓ Server APPEARS to defend against directory traversal:")
        print(f"  - Blocked {results['blocked_attempts']} suspicious requests")
        print(f"  - Returned 404 for {results['sanitized_attempts']} traversal attempts")
        print("\n  Verdict: Path sanitization and access controls are likely in place.")
    else:
        print("\n? Results inconclusive.")
        print(f"  - Most requests returned: {max(results['status_codes'], key=results['status_codes'].get)}")
        print("  - Monitor for unexpected file access or sensitive content exposure")


def directory_traversal_test():
    parser = argparse.ArgumentParser(
        description="Test server for directory traversal and path normalization vulnerabilities"
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g., https://yourdomain.com)"
    )
    parser.add_argument(
        "--base-path",
        default="/",
        help="Base path to append traversal payloads to (e.g., '/', '/download', '/api/files')"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of parallel workers"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Test duration in seconds"
    )
    
    args = parser.parse_args()
    
    asyncio.run(run_test(
        args.url,
        args.base_path,
        args.concurrency,
        args.duration
    ))


if __name__ == "__main__":
    directory_traversal_test()
