#!/usr/bin/env python3
"""
Auth Brute-Force Test
Exercises authentication endpoints with low-rate credential trials to detect
whether the server has account lockout, rate-limiting, or captcha defenses.
Sends configurable username/password combinations at controlled rates and records
HTTP 200/401/429 responses and any account lock notifications.
"""

import asyncio
import argparse
import aiohttp
import time
from collections import defaultdict
from datetime import datetime


# Common credential patterns to test (low-rate, intentionally simple)
CREDENTIAL_PATTERNS = [
    ("admin", "password"),
    ("admin", "12345678"),
    ("admin", "admin123"),
    ("admin", "qwerty"),
    ("root", "password"),
    ("root", "123456"),
    ("user", "password"),
    ("user", "12345678"),
    ("test", "password"),
    ("test", "test123"),
]


def get_payload_generator(param_style="json", endpoint_style="form"):
    """
    Factory to generate credential payloads for different endpoint styles.
    """
    def generator():
        idx = 0
        while True:
            username, password = CREDENTIAL_PATTERNS[idx % len(CREDENTIAL_PATTERNS)]
            idx += 1
            yield (username, password)
    return generator()


async def worker(session, url, auth_endpoint, concurrency_id, rate_limit_delay, max_attempts, results):
    """
    Worker coroutine that sends credential trials at controlled rate.
    
    Args:
        session: aiohttp ClientSession
        url: Base URL (scheme + domain)
        auth_endpoint: Relative path to auth endpoint (e.g., '/login', '/api/auth')
        concurrency_id: Worker identifier
        rate_limit_delay: Delay between requests in seconds (controls rate)
        max_attempts: Maximum trials per worker
        results: Shared dict to collect metrics
    """
    payload_gen = get_payload_generator()
    
    for attempt_num in range(max_attempts):
        try:
            username, password = next(payload_gen)
            
            # Prepare auth payload (JSON format, common in APIs)
            auth_payload = {
                "username": username,
                "password": password,
            }
            
            full_url = url.rstrip('/') + auth_endpoint
            
            start_time = time.time()
            try:
                async with session.post(
                    full_url,
                    json=auth_payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False
                ) as resp:
                    elapsed = time.time() - start_time
                    status = resp.status
                    body = await resp.text()
                    
                    results['total_requests'] += 1
                    results['status_codes'][status] += 1
                    results['latencies'].append(elapsed)
                    
                    # Check for account lock keywords
                    if any(keyword in body.lower() for keyword in ['locked', 'disabled', 'suspended', 'blocked']):
                        results['account_lock_detected'] += 1
                        results['lock_samples'].append(f"{username}: {status}")
                    
                    # Check for rate-limit keywords
                    if any(keyword in body.lower() for keyword in ['rate limit', 'too many', 'throttle', 'retry after']):
                        results['rate_limit_keyword_detected'] += 1
                    
                    # Check for captcha indicators
                    if any(keyword in body.lower() for keyword in ['captcha', 'human', 'verify', 'robot']):
                        results['captcha_detected'] += 1
                    
            except asyncio.TimeoutError:
                results['total_requests'] += 1
                results['timeouts'] += 1
            except aiohttp.ClientConnectionError:
                results['total_requests'] += 1
                results['connection_errors'] += 1
            except Exception as e:
                results['total_requests'] += 1
                results['other_errors'] += 1
            
            # Rate-limit delay between attempts (intentionally low to simulate controlled brute-force)
            await asyncio.sleep(rate_limit_delay)
        
        except Exception as e:
            results['other_errors'] += 1


async def run_test(url, auth_endpoint, concurrency, duration, rate_limit_delay):
    """
    Main test orchestrator: run concurrent workers for specified duration.
    
    Args:
        url: Target URL (e.g., https://yourdomain.com)
        auth_endpoint: Auth endpoint path (e.g., '/login', '/api/auth')
        concurrency: Number of parallel workers
        duration: Test duration in seconds
        rate_limit_delay: Delay between each request in seconds
    """
    results = {
        'total_requests': 0,
        'status_codes': defaultdict(int),
        'latencies': [],
        'timeouts': 0,
        'connection_errors': 0,
        'other_errors': 0,
        'account_lock_detected': 0,
        'lock_samples': [],
        'rate_limit_keyword_detected': 0,
        'captcha_detected': 0,
    }
    
    print(f"\n[*] Starting Auth Brute-Force Test")
    print(f"    Target: {url}{auth_endpoint}")
    print(f"    Concurrency: {concurrency}")
    print(f"    Duration: {duration}s")
    print(f"    Rate-Limit Delay: {rate_limit_delay}s between attempts")
    print(f"    Test Start Time: {datetime.now().isoformat()}\n")
    
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        
        # Start workers
        workers = [
            worker(session, url, auth_endpoint, i, rate_limit_delay, 1000, results)
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
    
    print(f"\nDefense Indicators:")
    print(f"  Account Locks Detected: {results['account_lock_detected']}")
    if results['lock_samples']:
        print(f"    Samples: {', '.join(results['lock_samples'][:5])}")
    
    print(f"  Rate-Limit Keywords: {results['rate_limit_keyword_detected']}")
    print(f"  Captcha Challenges: {results['captcha_detected']}")
    
    # Protection verdict
    print("\n" + "="*70)
    print("PROTECTION ANALYSIS")
    print("="*70)
    
    has_rate_limit = (
        429 in results['status_codes'] or 
        results['rate_limit_keyword_detected'] > 0
    )
    has_account_lock = (
        results['account_lock_detected'] > 0 or
        401 in results['status_codes'] and results['status_codes'][401] > concurrency * 2
    )
    has_captcha = results['captcha_detected'] > 0
    
    if has_rate_limit or has_account_lock or has_captcha:
        print("\n✓ Your server HAS authentication protections:")
        if has_rate_limit:
            print("  - Rate-limiting detected (HTTP 429 or similar)")
        if has_account_lock:
            print("  - Account lockout or progressive rejection detected")
        if has_captcha:
            print("  - Captcha or human verification challenge detected")
        print("\n  Verdict: Server defends against brute-force attacks.")
    else:
        success_count = results['status_codes'].get(200, 0)
        if success_count > concurrency:
            print("\n✗ Your server DOES NOT show clear brute-force protections:")
            print(f"  - Accepted {success_count} login attempts without rate-limiting")
            print(f"  - No account lockout or captcha detection")
            print("\n  Verdict: Add rate-limiting, account lockout, and captcha.")
        else:
            print("\n? Results inconclusive. Monitor for:")
            print(f"  - HTTP 429/403 (rate-limiting / firewall)")
            print(f"  - Repeated 401 (failed login attempts accepted)")
            print(f"  - Account lock keywords in responses")


def auth_bruteforce_test():
    parser = argparse.ArgumentParser(
        description="Test server brute-force defenses on authentication endpoints"
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g., https://yourdomain.com)"
    )
    parser.add_argument(
        "--auth-endpoint",
        default="/login",
        help="Authentication endpoint path"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of parallel brute-force workers"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Test duration in seconds"
    )
    parser.add_argument(
        "--rate-limit-delay",
        type=float,
        default=0.5,
        help="Delay in seconds between each credential attempt (per worker)"
    )
    
    args = parser.parse_args()
    
    asyncio.run(run_test(
        args.url,
        args.auth_endpoint,
        args.concurrency,
        args.duration,
        args.rate_limit_delay
    ))


if __name__ == "__main__":
    auth_bruteforce_test()
