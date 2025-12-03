#!/usr/bin/env python3
"""
Resource Exhaustion (CPU) Test
Triggers server-side expensive operations (safe, non-destructive inputs that
cause heavy processing) to see whether CPU-intensive requests are protected by
rate limits or cost-based throttling.
"""

import asyncio
import argparse
import aiohttp
import time
from collections import defaultdict
from datetime import datetime


# Payload patterns designed to trigger CPU-intensive operations on the server
# These are non-destructive but may cause expensive processing

CPU_EXPENSIVE_PAYLOADS = [
    # Regex backtracking patterns
    "a" * 1000 + "b",  # Will cause backtracking in greedy regex engines
    "(" * 100,  # Unbalanced parentheses
    "[a-z]" * 100 + "9",  # Regex character class mismatch
    "(a|ab)" * 50 + "c",  # Regex alternation backtracking
    
    # Large JSON parsing
    '{"a":' * 100 + '"value"' + '}' * 100,  # Deeply nested JSON
    '[' * 100 + '1' + ']' * 100,  # Deeply nested array
    
    # XML/HTML parsing stress
    "<div>" * 100 + "content" + "</div>" * 100,  # Deeply nested XML
    "<!--" * 100 + "comment" + "-->" * 100,  # Many comment starts
    
    # String manipulation patterns
    "x" * 10000,  # Large string
    "a" * 5000 + "b" * 5000,  # Concatenation heavy
    
    # Mathematical computation
    "1" * 1000,  # Large number parsing
    "9" * 999,  # Large numeric string
]


def payload_generator():
    """Generate CPU-intensive payloads cyclically."""
    idx = 0
    while True:
        payload = CPU_EXPENSIVE_PAYLOADS[idx % len(CPU_EXPENSIVE_PAYLOADS)]
        idx += 1
        yield payload


async def worker(session, url, endpoint, concurrency_id, max_attempts, results):
    """
    Worker coroutine that sends CPU-intensive payloads.
    
    Args:
        session: aiohttp ClientSession
        url: Base URL
        endpoint: Endpoint to send payloads to (e.g., '/api/process', '/search')
        concurrency_id: Worker identifier
        max_attempts: Maximum requests per worker
        results: Shared dict to collect metrics
    """
    gen = payload_generator()
    
    for attempt_num in range(max_attempts):
        try:
            payload = next(gen)
            
            full_url = url.rstrip('/') + endpoint
            
            # Send as POST JSON or URL parameter (endpoint-dependent)
            start_time = time.time()
            try:
                async with session.post(
                    full_url,
                    json={"input": payload},
                    timeout=aiohttp.ClientTimeout(total=60),
                    ssl=False
                ) as resp:
                    elapsed = time.time() - start_time
                    status = resp.status
                    body = await resp.text()
                    
                    results['total_requests'] += 1
                    results['status_codes'][status] += 1
                    results['latencies'].append(elapsed)
                    
                    # Track timeouts (server struggling)
                    if elapsed > 10:
                        results['slow_requests'] += 1
                        results['slow_samples'].append((payload[:50], elapsed))
                    
                    # Track rate-limit responses
                    if status == 429:
                        results['rate_limited'] += 1
                    
                    # Track errors
                    if status >= 500:
                        results['server_errors'] += 1
                    
                    # Check for error/crash indicators
                    if any(keyword in body.lower() for keyword in ['exception', 'traceback', 'error', 'fatal', 'crash']):
                        results['error_messages'] += 1
            
            except asyncio.TimeoutError:
                results['total_requests'] += 1
                results['timeouts'] += 1
                results['slow_requests'] += 1
            except aiohttp.ClientConnectionError:
                results['total_requests'] += 1
                results['connection_errors'] += 1
            except Exception as e:
                results['total_requests'] += 1
                results['other_errors'] += 1
            
            # Small delay between requests
            await asyncio.sleep(0.2)
        
        except Exception as e:
            results['other_errors'] += 1


async def run_test(url, endpoint, concurrency, duration):
    """
    Main test orchestrator: send CPU-intensive payloads for specified duration.
    
    Args:
        url: Target URL (e.g., https://yourdomain.com)
        endpoint: Endpoint to stress (e.g., '/api/process', '/search')
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
        'rate_limited': 0,
        'server_errors': 0,
        'error_messages': 0,
        'slow_requests': 0,
        'slow_samples': [],
    }
    
    print(f"\n[*] Starting Resource Exhaustion (CPU) Test")
    print(f"    Target: {url}{endpoint}")
    print(f"    Concurrency: {concurrency}")
    print(f"    Duration: {duration}s")
    print(f"    Test Start Time: {datetime.now().isoformat()}\n")
    
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.time()
        
        # Start workers
        workers = [
            worker(session, url, endpoint, i, 1000, results)
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
    print(f"  Timeouts (>60s): {results['timeouts']}")
    print(f"  Connection Errors: {results['connection_errors']}")
    print(f"  Other Errors: {results['other_errors']}")
    print(f"  Server Errors (5xx): {results['server_errors']}")
    print(f"  Error Messages in Response: {results['error_messages']}")
    
    if results['latencies']:
        latencies = sorted(results['latencies'])
        print(f"\nLatency Statistics:")
        print(f"  Min: {min(latencies):.3f}s")
        print(f"  Max: {max(latencies):.3f}s")
        print(f"  Avg: {sum(latencies) / len(latencies):.3f}s")
        print(f"  Median: {latencies[len(latencies)//2]:.3f}s")
        print(f"  Slow Requests (>10s): {results['slow_requests']}")
    
    # Protection verdict
    print("\n" + "="*70)
    print("PROTECTION ANALYSIS")
    print("="*70)
    
    has_throttling = (
        results['rate_limited'] > 0 or
        results['slow_requests'] > results['total_requests'] * 0.3
    )
    has_degradation = (
        results['server_errors'] > 0 or
        results['timeouts'] > 0 or
        results['error_messages'] > 0
    )
    
    # Check if latencies increased over time (sign of exhaustion)
    latency_increase = False
    if len(results['latencies']) > 10:
        first_half_avg = sum(results['latencies'][:len(results['latencies'])//2]) / (len(results['latencies'])//2)
        second_half_avg = sum(results['latencies'][len(results['latencies'])//2:]) / (len(results['latencies']) - len(results['latencies'])//2)
        if second_half_avg > first_half_avg * 1.5:
            latency_increase = True
    
    if has_throttling or latency_increase:
        print("\n✓ Server Shows CPU Protection Mechanisms:")
        if results['rate_limited'] > 0:
            print(f"  - Rate-limiting detected ({results['rate_limited']} 429 responses)")
        if results['slow_requests'] > 0:
            print(f"  - Response degradation detected ({results['slow_requests']} slow requests >10s)")
        if latency_increase:
            print(f"  - Latency increased under load (exhaustion detection)")
        print("\n  Verdict: Server protects against CPU exhaustion via throttling or graceful degradation.")
    elif has_degradation:
        print("\n⚠ Server Shows Stress Signs But Limited Protection:")
        print(f"  - Server errors: {results['server_errors']}")
        print(f"  - Timeouts: {results['timeouts']}")
        print("\n  Verdict: Server may lack explicit rate-limiting; consider adding CPU cost tracking.")
    else:
        print("\n✗ Limited CPU Exhaustion Protections Detected:")
        print(f"  - All {results['total_requests']} requests processed")
        print(f"  - No obvious rate-limiting or throttling")
        print(f"  - Consistent response times maintained")
        print("\n  Verdict: Add rate-limiting, request cost calculation, or CPU quota enforcement.")


def resource_exhaustion_cpu_test():
    parser = argparse.ArgumentParser(
        description="Test server CPU exhaustion defenses"
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g., https://yourdomain.com)"
    )
    parser.add_argument(
        "--endpoint",
        default="/api/process",
        help="Endpoint to send CPU-intensive payloads to"
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
        default=30,
        help="Test duration in seconds"
    )
    
    args = parser.parse_args()
    
    asyncio.run(run_test(
        args.url,
        args.endpoint,
        args.concurrency,
        args.duration
    ))


if __name__ == "__main__":
    resource_exhaustion_cpu_test()
