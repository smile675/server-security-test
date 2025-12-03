#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import time
from statistics import mean
from collections import defaultdict


PAYLOAD_LIMIT_KEYWORDS = [
    "payload too large",
    "request entity too large",
    "413",
    "request body too large",
    "entity too large",
    "413 request",
    "413 Request Entity Too Large",
]


async def large_generator(total_bytes: int, chunk_size: int = 65536):
    """Async generator that yields chunks up to total_bytes.

    Produces binary chunks to stream large request bodies without allocating
    the full payload in memory.
    """
    sent = 0
    chunk = b"0" * min(chunk_size, 8192)
    # generate repeating chunks until total reached
    while sent < total_bytes:
        remain = total_bytes - sent
        to_send = min(remain, len(chunk))
        yield chunk[:to_send]
        sent += to_send


async def worker(session, url, total_bytes, chunk_size, results):
    """Continuously send large POST requests and collect response info."""
    while True:
        start = time.perf_counter()
        try:
            data = large_generator(total_bytes, chunk_size)
            # Use stream upload
            async with session.post(url, data=data) as resp:
                latency = time.perf_counter() - start
                results["status_codes"][resp.status] += 1
                results["latencies"].append(latency)
                results["success"] += 1

                # read small portion of response to check body for messages
                try:
                    text = await resp.text()
                except Exception:
                    text = ""
                lowered = text.lower()
                for kw in PAYLOAD_LIMIT_KEYWORDS:
                    if kw in lowered:
                        results["limit_hits"] += 1
                        results["limit_messages"].add(kw)

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


async def run_test(url, concurrency, duration, size_mb, chunk_size):
    print("\nStarting Large Payload Test")
    print(f"URL: {url}")
    print(f"Concurrency: {concurrency}")
    print(f"Duration: {duration}s")
    print(f"Payload size per request: {size_mb} MB")
    print(f"Chunk size: {chunk_size} bytes")
    print("------------------------------------\n")

    total_bytes = int(size_mb * 1024 * 1024)

    results = {
        "success": 0,
        "fail": 0,
        "latencies": [],
        "status_codes": defaultdict(int),
        "timeouts": 0,
        "connection_resets": 0,
        "limit_hits": 0,
        "limit_messages": set(),
    }

    timeout = aiohttp.ClientTimeout(total=None)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [asyncio.create_task(worker(session, url, total_bytes, chunk_size, results))
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
    print(f"Total requests attempted: {total}")
    print(f"Successful: {results['success']}")
    print(f"Failed: {results['fail']}")
    print(f"Status codes: {dict(results['status_codes'])}")

    if results["latencies"]:
        print(f"Avg latency: {mean(results['latencies']):.4f}s")
        print(f"Fastest: {min(results['latencies']):.4f}s")
        print(f"Slowest: {max(results['latencies']):.4f}s")

    print(f"Connection resets: {results['connection_resets']}")
    print(f"Timeouts: {results['timeouts']}")
    print(f"Detected limit messages: {results['limit_messages']}")
    print(f"Limit hits: {results['limit_hits']}")

    # =======================
    # Protection Analysis
    # =======================
    print("\n====== PROTECTION ANALYSIS ======")
    protected = False

    # 1. Server rejects large payload with 413
    if results["status_codes"].get(413, 0) > 0 or results["limit_hits"] > 0:
        print("Server enforces request size limits (HTTP 413 or limit messages detected)")
        protected = True
    else:
        print("No explicit HTTP 413 or limit messages detected.")

    # 2. Connection resets (server closed connections while uploading)
    if results["connection_resets"] > 0:
        print(f"Server closed connections during upload ({results['connection_resets']} resets) — resource protection likely")
        protected = True

    # 3. Timeouts or 503/502
    if results["timeouts"] > 0 or results["status_codes"].get(503, 0) > 0 or results["status_codes"].get(502, 0) > 0:
        print("Timeouts or gateway errors observed — server or proxy limiting uploads")
        protected = True

    # 4. Very slow responses with failures
    if results["fail"] > 0 and results["latencies"]:
        avg_latency = mean(results["latencies"])
        if avg_latency > 30:
            print(f"High average latency under large uploads ({avg_latency:.2f}s) — server is throttling or overloaded")
            protected = True

    print("\n====== FINAL VERDICT ======")
    if protected:
        print("Your server HAS protections against large payload attacks (size limits, resets, or timeouts).")
    else:
        print("Your server DOES NOT appear to protect against large payload uploads. It may accept arbitrarily large bodies — consider adding limits.")

    print("============================\n")


def large_payload_test():
    parser = argparse.ArgumentParser(description="Test server resilience to very large request payloads")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--concurrency", type=int, default=5, help="Number of parallel upload workers")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    parser.add_argument("--size-mb", type=float, default=21.0, help="Payload size per request in MB")
    parser.add_argument("--chunk-size", type=int, default=65536, help="Upload chunk size in bytes")

    args = parser.parse_args()
    asyncio.run(run_test(args.url, args.concurrency, args.duration, args.size_mb, args.chunk_size))


if __name__ == "__main__":
    large_payload_test()
