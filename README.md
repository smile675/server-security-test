# Server Security Test
A Python command-line tool for performing basic load testing and security stress checks on any web server. This project is intended for educational purposes and safe testing on your own servers.

**Important: Do not run this tool on servers you do not own or have explicit permission to test. Running high-concurrency requests against third-party sites can be illegal and considered a DDoS attack.**

### Legal & Safety Warning
Sending high‑concurrency or repeated requests may be interpreted as DDoS behavior and can:
- trigger security filters
- cause temporary IP bans
- result in legal action

Only use this tool on:
- servers you own
- servers you manage
- servers where you have explicit permission

### What This Tool Does
This script helps you evaluate:

#### Server Performance Under Load
- High‑concurrency request handling
- Response latency
- Request throughput
- Stability under stress

#### Basic Server Protection Behaviour
- It can help verify whether your server:
- triggers rate‑limit protection
- blocks abusive behavior
- activates firewall rules (e.g., fail2ban, CSF, Cloudflare, Nginx limits)
- identifies suspicious patterns

**Note**
- The tool cannot bypass protections.
- If your server firewall blocks your IP during testing, that’s expected — your server is doing its job.


## Usage Instruction
- Clone or pull this repository to your local machine.
  ```bash
  git clone https://github.com/smile675/server-security-test.git
  cd server-security-test
  ```
- Create a Python virtual environment according to your OS requirements and activate it.
    ```bash
    # Windows (PowerShell)
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    ```
    ```bash 
    # Windows (Command Prompt)
    python -m venv venv
    venv\Scripts\activate.bat
    ```
    ```bash
    # Linux / macOS
    python3 -m venv venv
    source venv/bin/activate
    ```
- Install necessary packages 
    ```bash
    pip install -r requirements.txt
    ```
- Run each test individually using Python.
- If your server successfully protects against a test (e.g., triggers rate-limiting or blocks your IP), wait a few minutes before running another test to avoid being temporarily blocked.

## Tests Includes
The following tests are available. We will be keep adding more tests as we progress.

### Flood‑Resistance Test (flood_resistance_test.py)

**Description:**
A Python command-line tool that evaluates how a server responds to high-frequency requests. It detects whether the server has protections such as rate-limiting, firewall/WAF rules, or throttling mechanisms in place.

**How it Works:**
- Sends multiple concurrent GET requests to a target URL.
- Tracks response status codes (200, 403, 429, 503, etc.) and request latency.
- Checks response bodies for keywords indicating blocks or protection messages (e.g., “rate limit”, “temporarily blocked”, “access denied”).
- Provides a summary of request success/failure, latency statistics, and detected block messages.
- Gives a final verdict on whether the server shows signs of protection against high-rate/flood attacks.

**Expected Results:**
##### If server is protected:
- HTTP 429 (rate-limiting), 403 (WAF/firewall), or 503 (overload protection) may appear.
- Block/protection keywords detected in response body.
- Latency spikes for some requests.
- Final verdict: Your server HAS some protection against rapid/flood attacks.

##### If server is not protected:
- Most or all requests return HTTP 200.
- No block keywords detected.
- Latency remains consistently low.

**Final verdict:** 
Your server DOES NOT appear to protect against high-rate requests. It may be vulnerable to basic request-flood attacks.

**How to Run the test**
```bash
python tests/flood_resistance_test.py https://yourdomain.com --concurrency 50 --duration 20
```

### Slow Client Attack Test (slow_client_test.py)

**Description:**
A Python command-line tool that simulates slowloris-style attacks, where clients intentionally send requests with delayed/slow body transmission. It evaluates whether the server has timeout protections and can handle resource exhaustion from stalled connections.

**How it Works:**
- Sends multiple concurrent POST requests with intentionally slow payload transmission.
- Chunks the request body and delays between chunks to keep connections open longer than normal.
- Tracks response status codes, connection resets, and timeout errors.
- Checks response bodies for timeout-related keywords.
- Provides a summary of timeouts, connection resets, and latency patterns.
- Gives a final verdict on whether the server protects against slow client attacks.

**Expected Results:**
##### If server is protected:
- HTTP 408 (Request Timeout) or 504 (Gateway Timeout) responses.
- Connection resets when clients delay too long.
- Timeout keywords detected in response body.
- High latency followed by request failures.
- Final verdict: Your server HAS protection against slow client attacks.

##### If server is not protected:
- Most or all requests return HTTP 200 despite slow transmission.
- No connection resets or timeouts.
- Server continues to accept slow requests indefinitely.
- Final verdict: Your server DOES NOT appear to protect against slow client attacks. It may be vulnerable to slowloris or resource exhaustion attacks.

**How to Run the test**
```bash
python tests/slow_client_test.py https://yourdomain.com --concurrency 10 --duration 15 --delay 2.0
```

**Arguments:**
- `--concurrency` (int, default 10): Number of parallel slow clients
- `--duration` (int, default 10): Test duration in seconds
- `--delay` (float, default 2.0): Delay between payload chunks in seconds

### Large Payload Test (large_payload_test.py)

**Description:**
Simulates clients uploading very large request bodies to a target endpoint to verify whether the server enforces request size limits, times out, or closes connections during heavy uploads.

**How it Works:**
- Streams large POST bodies (configurable size per request) in small chunks to avoid allocating the entire payload in memory.
- Runs multiple parallel upload workers to increase load and exercise server/proxy limits.
- Tracks HTTP status codes, latencies, connection resets, timeouts, and looks for common "payload too large" messages in responses.
- Produces a summary and a protection analysis (detects HTTP 413, resets, 502/503/504 gateway errors, and related behavior).

**Expected Results:**
##### If server is protected:
- HTTP 413 (Payload Too Large) or explicit limit messages in responses.
- Connection resets during upload (server/proxy closes uploads it deems too large).
- Gateway errors/timeouts (502/503/504) if upstream refuses large uploads.
- Final verdict: Server enforces size limits or otherwise protects against large uploads.

##### If server is not protected:
- Most uploads complete successfully (HTTP 200 or similar).
- No explicit limit messages or connection resets.
- Final verdict: Server may accept arbitrarily large uploads — consider adding request size limits and proxy protections.

**How to Run the test**
```bash
python tests/large_payload_test.py https://yourdomain.com
```

**Arguments:**
- `--concurrency` (int, default 5): Number of parallel upload workers
- `--duration` (int, default 30): Test duration in seconds
- `--size-mb` (float, default 21.0): Payload size per request in MB
- `--chunk-size` (int, default 65536): Upload chunk size in bytes

### Header Injection Test (header_injection_test.py)

**Description:**
Sends requests with malformed, oversized, or numerous header fields to discover header parsing and validation limits. The test helps detect whether front-end servers or WAFs properly limit header sizes and counts and whether malformed headers cause connection resets or parsing errors.

**How it Works:**
- Sends requests that exercise a range of header abuses: very long header values (e.g., `User-Agent`), extremely large `Cookie` headers, many distinct headers, duplicated header values, and attempts at illegal header names.
- Tracks HTTP status codes (400, 431, 403, etc.), latencies, connection resets, and client-side exceptions.
- Scans response bodies for common block or error messages (e.g., "Header Fields Too Large", "bad request").
- Produces a summary and a protection analysis indicating whether header limits or WAF protections are in effect.

**Expected Results:**
##### If server is protected:
- HTTP 431 (Header Fields Too Large) or HTTP 400 for malformed headers.
- HTTP 403 if a WAF/firewall blocks requests.
- Connection resets or socket errors when the server/proxy rejects oversized headers.
- Final verdict: Server enforces header limits and resists header-based abuse.

##### If server is not protected:
- Most requests succeed (HTTP 200) even with oversized/duplicate headers.
- No header-specific error messages detected.
- Final verdict: Consider enforcing header size/count limits at the proxy (e.g., Nginx) or WAF.

**How to Run the test**
```bash
python tests/header_injection_test.py https://yourdomain.com
```

**Arguments:**
- `--concurrency` (int, default 5): Parallel workers
- `--duration` (int, default 20): Test duration in seconds
- `--max-header-kb` (int, default 64): Approximate maximum header size to attempt (KB)
- `--many-headers` (int, default 200): Number of headers to send in the "many headers" case
- `--duplicate-count` (int, default 50): Number of duplicate values simulated (comma-separated simulation)

### SQL Injection Test (sql_injection_test.py)

**Description:**
Sends a curated set of benign-but-malicious-looking SQL injection payloads (via URL parameters and request bodies) to detect whether the server has input validation, WAF protections, or error-message leakage that indicates potential SQL injection vulnerability.

**How it Works:**
- Sends a list of recognizable SQL injection patterns (e.g., `' OR '1'='1`, `UNION SELECT`, boolean probes) as URL parameters.
- Tracks HTTP status codes, latencies, and connection-level errors.
- Scans response bodies for:
  - **WAF keywords**: "sql injection", "attack detected", "blocked", "403" (indicating WAF/protection).
  - **Database error keywords**: "sql syntax", "table not found", "column not found", "postgresql", "mysql", etc. (indicating error leakage).
- Produces a summary and protection analysis.

**Expected Results:**
##### If server is protected:
- HTTP 403 (WAF blocks malicious patterns).
- HTTP 400 (Server rejects suspicious input).
- No database error messages in responses (error suppression).
- Final verdict: Server has protections against SQL injection.

##### If server is vulnerable:
- Payloads accepted without rejection (HTTP 200).
- Database error messages leaked in responses (e.g., "SQL syntax error", "table not found").
- Final verdict: Review input validation, enable error suppression, and deploy WAF rules.

**How to Run the test**
```bash
python tests/sql_injection_test.py https://yourdomain.com/search 
```

**Arguments:**
- `url`: Target URL (e.g., `https://yourdomain.com/search`)
- `--param` (str, default "q"): Query parameter name to inject payloads into
- `--concurrency` (int, default 5): Parallel workers
- `--duration` (int, default 20): Test duration in seconds

### Protocol Confusion Test (protocol_confusion_test.py)

**Description:**
Sends intentionally malformed HTTP requests to validate the server's protocol-compliance and parser robustness. It tests the server's ability to handle missing CRLF sequences, invalid HTTP methods, wrong protocol versions, malformed chunk boundaries, and other HTTP grammar violations. The goal is to discover whether the server fails safely with graceful 4xx errors or if it crashes, hangs, or exhibits unexpected behavior.

**How it Works:**
- Sends a series of malformed HTTP requests with various violations (e.g., `GET / HTTP/2.5`, missing colons in headers, invalid chunked encoding, oversized Content-Length, null bytes, etc.).
- Uses raw sockets to send requests directly (bypassing HTTP client libraries that may auto-correct).
- Tracks outcomes: HTTP responses (including status codes), connection resets, timeouts, connection refusals, and exceptions.
- Produces a summary and protection analysis based on observed behavior.

**Expected Results:**
##### If server is robust:
- Malformed requests return HTTP 400 (Bad Request) or 405 (Method Not Allowed).
- Connection resets for egregiously malformed input (protection against parser exploits).
- No timeouts or server crashes.
- Final verdict: Server gracefully rejects malformed HTTP.

##### If server is vulnerable:
- Malformed requests accepted without error (HTTP 200).
- Server timeouts or hangs on certain patterns.
- HTTP 500 (Internal Server Error) responses.
- Unexplained connection resets or crashes.
- Final verdict: Server parser may be vulnerable to DoS or protocol confusion attacks.

**How to Run the test**
```bash
python tests/protocol_confusion_test.py yourdomain.com
```

**Arguments:**
- `host`: Target hostname (e.g., `yourdomain.com`)
- `--port` (int): Target port (default 443 if scheme is https)
- `--scheme` (str): Protocol scheme (`http` or `https`)
- `--duration` (int): Test duration in seconds

### Malformed Request Test (malformed_request_test.py)

**Description:**
Sends requests with structurally invalid payloads and header/body mismatches (e.g., `Content-Length` not matching body size, chunked encoding errors, broken multipart boundaries) to verify whether the server properly validates request framing and returns safe error responses rather than exposing stack traces or leaking internal state.

**How it Works:**
- Generates a series of malformed requests with 13 different framing violation patterns (e.g., `Content-Length` smaller than body, mismatched `Content-Length`, chunked encoding with invalid chunks, broken multipart boundaries, conflicting `Transfer-Encoding` and `Content-Length` headers).
- Sends each malformed request and tracks HTTP status codes, latencies, and response content.
- Scans response bodies for error-leakage keywords (e.g., "traceback", "exception", "file not found", "module error", stack traces).
- Produces a summary and a protection analysis indicating whether the server safely handles malformed input.

**Expected Results:**
##### If server is robust:
- HTTP 400 (Bad Request), 411 (Length Required), or 413 (Payload Too Large) for framing violations.
- Connection resets for protocol-level violations (expected defensive behavior).
- No stack traces, exception details, or internal error messages in responses.
- Final verdict: Server safely rejects malformed requests and suppresses error leakage.

##### If server is vulnerable:
- Malformed requests accepted (HTTP 200) without detection.
- Error messages, stack traces, or file paths visible in responses.
- No defensive connection resets or proper error responses.
- Final verdict: Server may expose internal details on malformed input; review error suppression and request validation.

**How to Run the test**
```bash
python tests/malformed_request_test.py https://yourdomain.com
```

**Arguments:**
- `url`: Target URL (e.g., `https://yourdomain.com`)
- `--concurrency` (int): Number of parallel workers
- `--duration` (int): Test duration in seconds

# Contribution Guide

If you would like to contribute to this project, please follow the [Contribution Guide](CONTRIBUTING.md) for instructions on how to contribute effectively.
