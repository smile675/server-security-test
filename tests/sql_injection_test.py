#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
from urllib.parse import urljoin, urlencode
import time
from statistics import mean
from collections import defaultdict


# Benign but recognizable SQL injection payloads for detection
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT NULL --",
    "1' AND '1'='1",
    "1' AND 1=1 --",
    "' OR 'a'='a",
    "'; DROP TABLE users; --",
    "' OR TRUE --",
    "1' OR '1'='1' /*",
    "' UNION ALL SELECT NULL --",
    "1 UNION SELECT username, password FROM users --",
    "' AND 1=1 UNION SELECT 1,2,3 --",
]

# Common database error signatures that indicate potential vulnerability
DB_ERROR_KEYWORDS = [
    "sql syntax",
    "mysql_fetch",
    "sql error",
    "database error",
    "postgresql",
    "sqlalchemy",
    "sqlite",
    "odbc",
    "jdbc",
    "connection failed",
    "table not found",
    "column not found",
    "syntax error",
]

# WAF/Protection keywords
WAF_KEYWORDS = [
    "sql injection",
    "attack detected",
    "malicious",
    "blocked",
    "forbidden",
    "403",
    "waf",
]


async def worker(session, base_url, param_name, payload_generator, results):
    """Send SQL injection payloads and collect metrics."""
    while True:
        start = time.perf_counter()
        try:
            payload = next(payload_generator)
            
            # Test 1: URL parameter
            params = {param_name: payload}
            url = f"{base_url}?{urlencode(params)}"
            
            try:
                async with session.get(url) as resp:
                    latency = time.perf_counter() - start
                    results["status_codes"][resp.status] += 1
                    results["latencies"].append(latency)
                    results["success"] += 1
                    
                    text = await resp.text()
                    lowered = text.lower()
                    
                    # Check for WAF blocks
                    for kw in WAF_KEYWORDS:
                        if kw in lowered:
                            results["waf_hits"] += 1
                            results["waf_messages"].add(kw)
                    
                    # Check for database error leakage
                    for kw in DB_ERROR_KEYWORDS:
                        if kw in lowered:
                            results["db_errors"] += 1
                            results["db_error_keywords"].add(kw)
                            results["error_samples"].append((payload, kw))
            
            except asyncio.TimeoutError:
                results["timeouts"] += 1
                results["fail"] += 1
            except aiohttp.ClientConnectionError:
                results["connection_resets"] += 1
                results["fail"] += 1
            except Exception as e:
                results["fail"] += 1
        
        except asyncio.CancelledError:
            break
        except StopIteration:
            break
        except Exception:
            results["fail"] += 1


def payload_generator_factory():
    """Yield SQL injection payloads cyclically."""
    while True:
        for p in SQL_PAYLOADS:
            yield p


async def run_test(url, param_name, concurrency, duration):
    print("\nStarting SQL Injection Test")
    print(f"URL: {url}")
    print(f"Parameter name: {param_name}")
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
        "waf_hits": 0,
        "waf_messages": set(),
        "db_errors": 0,
        "db_error_keywords": set(),
        "error_samples": [],
    }
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        gen = payload_generator_factory()
        tasks = [asyncio.create_task(worker(session, url, param_name, gen, results))
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
    print(f"WAF block hits: {results['waf_hits']}")
    print(f"WAF keywords: {results['waf_messages']}")
    print(f"Database error exposures: {results['db_errors']}")
    print(f"DB error keywords: {results['db_error_keywords']}")
    
    if results["error_samples"]:
        print("\nSample error exposures (first 5):")
        for payload, keyword in results["error_samples"][:5]:
            print(f"  - Payload: {payload[:50]}... → Leaked: {keyword}")
    
    # Protection analysis
    print("\n====== PROTECTION ANALYSIS ======")
    protected = False
    vulnerable = False
    
    if results["waf_hits"] > 0:
        print("WAF/Protection detected: SQL injection payloads were blocked or logged.")
        protected = True
    else:
        print("No explicit WAF blocks detected.")
    
    if results["status_codes"].get(403, 0) > 0:
        print("HTTP 403 Forbidden returned — likely WAF protection.")
        protected = True
    
    if results["status_codes"].get(400, 0) > 0:
        print("HTTP 400 Bad Request — server rejected malicious-looking input.")
        protected = True
    
    if results["db_errors"] > 0:
        print(f"Database error messages exposed ({results['db_errors']} instances).")
        print("This indicates potential SQL injection vulnerability or error message leakage.")
        vulnerable = True
    
    if results["connection_resets"] > 0:
        print(f"Connection resets ({results['connection_resets']}) — server/WAF may be dropping malicious requests.")
        protected = True
    
    print("\n====== FINAL VERDICT ======")
    if vulnerable and not protected:
        print("WARNING: Your server appears VULNERABLE to SQL injection or information disclosure.")
        print("Database error messages are being leaked. Review input validation and error handling.")
    elif protected:
        print("Your server shows SQL injection protections (WAF, input validation, error suppression).")
    else:
        print("No clear protections or vulnerabilities detected. Payloads were accepted silently.")
        print("Recommend: add input validation, error suppression, and WAF rules.")
    
    print("============================\n")


def sql_injection_test():
    parser = argparse.ArgumentParser(
        description="Test server resilience against SQL injection attacks"
    )
    parser.add_argument("url", help="Target URL (e.g., https://yourdomain.com/search)")
    parser.add_argument("--param", type=str, default="q", help="Query parameter name (default: q)")
    parser.add_argument("--concurrency", type=int, default=5, help="Parallel workers")
    parser.add_argument("--duration", type=int, default=20, help="Duration seconds")
    
    args = parser.parse_args()
    asyncio.run(run_test(args.url, args.param, args.concurrency, args.duration))


if __name__ == "__main__":
    sql_injection_test()
