#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import time
from statistics import mean
from collections import defaultdict


async def worker(session, url, delay_seconds, results):
    """Send POST requests with intentionally slow body transmission."""
    while True:
        start = time.perf_counter()
        try:
            # Create a slow payload generator that delays between chunks
            async def slow_body():
                body = b"x" * 1024  # 1KB payload
                yield body[:512]
                await asyncio.sleep(delay_seconds)
                yield body[512:]

            async with session.post(url, data=slow_body()) as resp:
                latency = time.perf_counter() - start

                # Track status codes
                results["status_codes"][resp.status] += 1
                results["latencies"].append(latency)
                results["success"] += 1

                # Detect timeout or protection keywords
                text = await resp.text()
                lowered = text.lower()
                for keyword in TIMEOUT_KEYWORDS:
                    if keyword in lowered:
                        results["timeout_hits"] += 1
                        results["timeout_messages"].add(keyword)

        except asyncio.CancelledError:
            break

        except asyncio.TimeoutError:
            results["timeouts"] += 1
            results["fail"] += 1

        except aiohttp.ClientConnectionError:
            results["connection_resets"] += 1
            results["fail"] += 1

        except Exception:
            results["fail"] += 1


TIMEOUT_KEYWORDS = [
    "timeout",
    "timed out",
    "request timeout",
    "connection timeout",
    "read timeout",
    "idle timeout",
    "gateway timeout",
]


async def run_test(url, concurrency, duration, delay):
    print("\nStarting Slow Client Attack Test")
    print(f"URL: {url}")
    print(f"Concurrency: {concurrency}")
    print(f"Duration: {duration}s")
    print(f"Delay per chunk: {delay}s")
    print("------------------------------------\n")

    results = {
        "success": 0,
        "fail": 0,
        "latencies": [],
        "status_codes": defaultdict(int),
        "timeouts": 0,
        "connection_resets": 0,
        "timeout_hits": 0,
        "timeout_messages": set(),
    }

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(worker(session, url, delay, results))
                 for _ in range(concurrency)]

        try:
            await asyncio.sleep(duration)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # =======================
    # Summary
    # =======================
    print("\n====== RAW RESULT DATA ======")
    total = results["success"] + results["fail"]
    print(f"Total requests: {total}")
    print(f"Successful: {results['success']}")
    print(f"Failed: {results['fail']}")
    print(f"Timeouts: {results['timeouts']}")
    print(f"Connection resets: {results['connection_resets']}")
    print(f"Status codes: {dict(results['status_codes'])}")

    if results["latencies"]:
        print(f"Avg latency: {mean(results['latencies']):.4f}s")
        print(f"Fastest: {min(results['latencies']):.4f}s")
        print(f"Slowest: {max(results['latencies']):.4f}s")

    print(f"Timeout message hits: {results['timeout_hits']}")
    print(f"Detected timeout messages: {results['timeout_messages']}")

    # =======================
    # Protection Evaluation
    # =======================
    print("\n====== PROTECTION ANALYSIS ======")

    protected = False

    # 1. Connection resets
    if results["connection_resets"] > 0:
        print(f"Server closed slow connections ({results['connection_resets']} resets)")
        protected = True
    else:
        print("No connection resets detected.")

    # 2. Timeout errors
    if results["timeouts"] > 0:
        print(f"Server enforced timeouts ({results['timeouts']} timeouts)")
        protected = True

    # 3. HTTP 408 (Request Timeout)
    if results["status_codes"].get(408, 0) > 0:
        print(f"HTTP 408 Request Timeout detected ({results['status_codes'][408]} responses)")
        protected = True

    # 4. HTTP 504 (Gateway Timeout)
    if results["status_codes"].get(504, 0) > 0:
        print(f"HTTP 504 Gateway Timeout detected ({results['status_codes'][504]} responses)")
        protected = True

    # 5. Timeout keywords in response
    if results["timeout_hits"] > 0:
        print(f"Timeout protection messages detected in responses")
        print(f"Keywords: {results['timeout_messages']}")
        protected = True

    # 6. High latency with failures
    if results["fail"] > 0 and results["latencies"]:
        avg_latency = mean(results["latencies"])
        if avg_latency > 10:
            print(f"High latency with failures suggests throttling/protection ({avg_latency:.2f}s avg)")
            protected = True

    print("\n====== FINAL VERDICT ======")
    if protected:
        print("Your server HAS protection against slow client attacks.")
        print("It enforces timeouts, closes slow connections, or implements rate-limiting.")
    else:
        print("Your server DOES NOT appear to protect against slow client attacks.")
        print("It may be vulnerable to slowloris-style attacks or resource exhaustion.")

    print("============================\n")


def slow_client_test():
    parser = argparse.ArgumentParser(
        description="Test server resilience to slow client attacks (slowloris-style)"
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of parallel slow clients")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in seconds")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between payload chunks (seconds)")

    args = parser.parse_args()
    asyncio.run(run_test(args.url, args.concurrency, args.duration, args.delay))


if __name__ == "__main__":
    slow_client_test()
