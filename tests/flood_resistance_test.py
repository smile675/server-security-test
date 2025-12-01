#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import time
from statistics import mean
from collections import defaultdict


BLOCK_KEYWORDS = [
    "rate limit",
    "too many requests",
    "please wait a few minutes",
    "temporarily blocked",
    "retry later",
    "access denied",
    "forbidden",
    "not allowed",
    "ddos",
    "protection",
]


async def worker(session, url, results):
    """Repeatedly send requests and analyze responses."""
    while True:
        start = time.perf_counter()
        try:
            async with session.get(url) as resp:
                text = await resp.text()
                latency = time.perf_counter() - start

                # Track status codes
                results["status_codes"][resp.status] += 1

                # Track latencies
                results["latencies"].append(latency)
                results["success"] += 1

                # Detect block keywords
                lowered = text.lower()
                for keyword in BLOCK_KEYWORDS:
                    if keyword in lowered:
                        results["block_hits"] += 1
                        results["block_messages"].add(keyword)

        except asyncio.CancelledError:
            break

        except Exception:
            results["fail"] += 1


async def run_test(url, concurrency, duration):
    print("\nStarting DDOS protection test")
    print(f"URL: {url}")
    print(f"Concurrency: {concurrency}")
    print(f"Duration: {duration}s")
    print("------------------------------------\n")

    results = {
        "success": 0,
        "fail": 0,
        "latencies": [],
        "status_codes": defaultdict(int),
        "block_hits": 0,
        "block_messages": set(),
    }

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(worker(session, url, results))
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
    print(f"Status codes: {dict(results['status_codes'])}")

    if results["latencies"]:
        print(f"Avg latency: {mean(results['latencies']):.4f}s")
        print(f"Fastest: {min(results['latencies']):.4f}s")
        print(f"Slowest: {max(results['latencies']):.4f}s")

    print(f"Detected block messages: {results['block_messages']}")
    print(f"Block hits: {results['block_hits']}")

    # =======================
    # Protection Evaluation
    # =======================
    print("\n====== PROTECTION ANALYSIS ======")

    protected = False

    # 1. Rate limiting (429)
    if results["status_codes"].get(429, 0) > 0:
        print("Rate‑limiting detected (HTTP 429)")
        protected = True
    else:
        print("No HTTP 429 rate limiting detected.")

    # 2. WAF / security block (403)
    if results["status_codes"].get(403, 0) > 0:
        print("Firewall/WAF blocking detected (HTTP 403)")
        protected = True

    # 3. Service overload (503)
    if results["status_codes"].get(503, 0) > 0:
        print("Server returned 503 Service Unavailable – overload protection active")
        protected = True

    # 4. Keyword block detection
    if results["block_hits"] > 0:
        print("Block/Protection messages detected in response body")
        protected = True
        print(f"Keywords: {results['block_messages']}")

    # 5. Latency spike detection
    if results["latencies"]:
        slow = max(results["latencies"])
        if slow > 5:
            print("Severe slowdown (likely throttling)")
            protected = True

    print("\n====== FINAL VERDICT ======")
    if protected:
        print("Your server HAS some protection against rapid/flood attacks.")
    else:
        print("Your server DOES NOT appear to protect against high - rate requests.")
        print("It may be vulnerable to basic request - flood attacks.")

    print("============================\n")


def flood_resistance_test():
    parser = argparse.ArgumentParser(description="DDoS / Load Test + Protection Detection")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of parallel workers")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in seconds")

    args = parser.parse_args()
    asyncio.run(run_test(args.url, args.concurrency, args.duration))


if __name__ == "__main__":
    flood_resistance_test()
