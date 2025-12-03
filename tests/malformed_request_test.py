#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import time
from statistics import mean
from collections import defaultdict


# Error/stack trace keywords that indicate information leakage
ERROR_KEYWORDS = [
    "traceback",
    "stack trace",
    "exception",
    "error at line",
    "file not found",
    "module not found",
    "import error",
    "attribute error",
    "type error",
    "value error",
    "key error",
    "index error",
    "database error",
    "connection error",
    "timeout error",
    "permission denied",
    "access denied",
    "internal server error",
]


async def worker(session, url, case_generator, results):
    """Send malformed requests and collect metrics."""
    while True:
        try:
            request_data, description = next(case_generator)
            start = time.perf_counter()
            
            try:
                # Send the request
                method = request_data.get("method", "POST")
                headers = request_data.get("headers", {})
                body = request_data.get("body", None)
                
                async with session.request(method, url, headers=headers, data=body) as resp:
                    latency = time.perf_counter() - start
                    results["status_codes"][resp.status] += 1
                    results["latencies"].append(latency)
                    results["success"] += 1
                    
                    # Read response body to check for error leakage
                    try:
                        text = await resp.text()
                    except Exception:
                        text = ""
                    
                    lowered = text.lower()
                    
                    # Check for error/stack trace leakage
                    for kw in ERROR_KEYWORDS:
                        if kw in lowered:
                            results["error_leaks"] += 1
                            results["error_keywords"].add(kw)
                            results["error_samples"].append((description, kw))
            
            except asyncio.TimeoutError:
                results["timeouts"] += 1
                results["fail"] += 1
            except aiohttp.ClientConnectionError:
                results["connection_resets"] += 1
                results["fail"] += 1
            except Exception as e:
                results["fail"] += 1
                results["exceptions"].append(str(type(e).__name__))
        
        except asyncio.CancelledError:
            break
        except StopIteration:
            break
        except Exception:
            results["fail"] += 1


def case_generator_factory():
    """Yield malformed request cases."""
    # Case 1: Content-Length greater than actual body
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "100"},
        "body": b"short"
    }, "content-length-greater-than-body")
    
    # Case 2: Content-Length less than actual body (server may truncate or error)
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "2"},
        "body": b"this is a longer body"
    }, "content-length-less-than-body")
    
    # Case 3: Negative Content-Length
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "-10"},
        "body": b"hello"
    }, "negative-content-length")
    
    # Case 4: Invalid Content-Length (non-numeric)
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "invalid"},
        "body": b"hello"
    }, "non-numeric-content-length")
    
    # Case 5: Chunked encoding with missing chunk size
    yield ({
        "method": "POST",
        "headers": {"Transfer-Encoding": "chunked"},
        "body": b"\r\nhello\r\n0\r\n\r\n"
    }, "chunked-missing-size")
    
    # Case 6: Chunked encoding with invalid hex chunk size
    yield ({
        "method": "POST",
        "headers": {"Transfer-Encoding": "chunked"},
        "body": b"ZZZ\r\nhello\r\n0\r\n\r\n"
    }, "chunked-invalid-hex-size")
    
    # Case 7: Both Content-Length and Transfer-Encoding (conflicting)
    yield ({
        "method": "POST",
        "headers": {
            "Content-Length": "5",
            "Transfer-Encoding": "chunked"
        },
        "body": b"5\r\nhello\r\n0\r\n\r\n"
    }, "content-length-and-transfer-encoding")
    
    # Case 8: Duplicate Content-Length with different values
    # Note: aiohttp client may not allow this directly, but we simulate the intent
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "5"},
        "body": b"hello"
    }, "duplicate-content-length-intent")
    
    # Case 9: Multipart with broken boundary
    yield ({
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        "body": b"------WebKitFormBoundaryMISSING\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue"
    }, "multipart-broken-boundary")
    
    # Case 10: Multipart with missing final boundary
    yield ({
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        "body": b"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"
    }, "multipart-missing-final-boundary")
    
    # Case 11: Multipart with no boundary marker at all
    yield ({
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        "body": b"This is not a valid multipart body at all."
    }, "multipart-no-boundary-marker")
    
    # Case 12: Very large Content-Length with small body
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "999999999"},
        "body": b"x"
    }, "oversized-content-length")
    
    # Case 13: Zero Content-Length with actual body
    yield ({
        "method": "POST",
        "headers": {"Content-Length": "0"},
        "body": b"unexpected body content"
    }, "zero-content-length-with-body")


async def run_test(url, concurrency, duration):
    print("\nStarting Malformed Request Test")
    print(f"URL: {url}")
    print(f"Concurrency: {concurrency}")
    print(f"Duration: {duration}s")
    print("------------------------------------\n")
    
    results = {
        "success": 0,
        "fail": 0,
        "latencies": [],
        "status_codes": defaultdict(int),
        "timeouts": 0,
        "connection_resets": 0,
        "error_leaks": 0,
        "error_keywords": set(),
        "error_samples": [],
        "exceptions": [],
    }
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        gen = case_generator_factory()
        tasks = [asyncio.create_task(worker(session, url, gen, results))
                 for _ in range(concurrency)]
        
        try:
            await asyncio.sleep(duration)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    
    # Summary
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
    print(f"Error/stack trace leaks: {results['error_leaks']}")
    print(f"Error keywords detected: {results['error_keywords']}")
    
    if results["error_samples"]:
        print("\nError leakage samples (first 5):")
        for desc, kw in results["error_samples"][:5]:
            print(f"  - {desc} → leaked: {kw}")
    
    if results["exceptions"]:
        print(f"Client exceptions: {set(results['exceptions'])}")
    
    # Protection analysis
    print("\n====== PROTECTION ANALYSIS ======")
    protected = False
    vulnerable = False
    
    if results["status_codes"].get(400, 0) > 0:
        print("HTTP 400 (Bad Request) responses — server rejects malformed framing.")
        protected = True
    
    if results["status_codes"].get(413, 0) > 0:
        print("HTTP 413 (Payload Too Large) — server enforces size limits.")
        protected = True
    
    if results["status_codes"].get(411, 0) > 0:
        print("HTTP 411 (Length Required) — server enforces Content-Length validation.")
        protected = True
    
    if results["status_codes"].get(500, 0) > 0:
        print("HTTP 500 (Internal Server Error) — server encountered errors on malformed input.")
        vulnerable = True
    
    if results["error_leaks"] > 0:
        print(f"Error/stack trace leakage detected ({results['error_leaks']} instances).")
        print("Information disclosure vulnerability: error messages exposed to client.")
        vulnerable = True
    
    if results["connection_resets"] > 0:
        print(f"Connection resets ({results['connection_resets']}) — server/proxy rejected requests.")
        protected = True
    
    if results["timeouts"] > 0:
        print(f"Timeouts ({results['timeouts']}) — server may hang on malformed framing.")
        vulnerable = True
    
    print("\n====== FINAL VERDICT ======")
    if vulnerable and not protected:
        print("WARNING: Server may be VULNERABLE to malformed request attacks.")
        print("Error leakage detected or timeouts/crashes observed.")
        print("Recommendations: suppress error details, validate request framing, implement timeouts.")
    elif protected:
        print("Server shows good input validation: rejects malformed requests gracefully.")
    else:
        print("No clear signals. Server may be silently discarding or accepting malformed input.")
    
    print("============================\n")


def malformed_request_test():
    parser = argparse.ArgumentParser(
        description="Test server robustness against malformed request framing"
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--concurrency", type=int, default=5, help="Parallel workers")
    parser.add_argument("--duration", type=int, default=20, help="Test duration in seconds")
    
    args = parser.parse_args()
    asyncio.run(run_test(args.url, args.concurrency, args.duration))


if __name__ == "__main__":
    malformed_request_test()
