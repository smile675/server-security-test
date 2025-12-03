# Test Plans — TODO

This file lists planned security tests for the project. Each item includes a short description of what the test will check and the signals it will record. Tests marked with `[x]` are already implemented.

> Note: These tests are for defensive, educational use only. Always obtain explicit permission to test a server and start with low concurrency/duration.

- [x] `flood_resistance_test.py`

  Description:

  The Flood Resistance test stresses the HTTP(s) endpoint with many concurrent GET requests to evaluate the server's behavior under high request rates. It measures per-request latencies, aggregates HTTP status codes, and scans response bodies for block/protection keywords (e.g., “rate limit”, “temporarily blocked”, “access denied”). Key detection signals include HTTP 429 (rate limiting), HTTP 403 (WAF/firewall), HTTP 503 (service overload), latency spikes (max latency > 5 s), and textual block messages. The test outputs a raw summary and a protection verdict indicating whether the server shows signs of rate-limiting or other flood protections.

- [x] `slow_client_test.py`

  Description:

  The Slow Client test (slowloris-style) simulates clients that send request bodies very slowly (chunked with delays) to keep TCP connections open and consume connection slots. It records timeouts, connection resets, HTTP 408/504 responses, and latency profiles. The test helps detect whether the server enforces request read timeouts, idle-connection timeouts, or actively closes slow connections to protect resources. Detection signals include per-request `asyncio.TimeoutError`, `aiohttp.ClientConnectionError` (resets), HTTP 408/504 responses, and timeout-indicating keywords in responses. Start with small concurrency and short durations.

- [x] `large_payload_test.py`

  Description:

  The Large Payload test sends POST or PUT requests with increasingly large payloads (configurable sizes and step increments) to evaluate server upload limits and memory/IO protections. It checks for HTTP 413 (Payload Too Large), HTTP 400 responses, connection drops during upload, and server-side memory or process crashes. The test should progressively increase payload size so that the operator can pinpoint threshold behavior. Results include counts of payload rejects, status codes, and latencies for large uploads. This test helps validate server and application-layer limits (e.g., nginx `client_max_body_size`, application validation) and informs safe upload size configuration.

- [x] `header_injection_test.py`

  Description:

  The Header Injection test sends requests with malformed, oversized, or numerous header fields to discover header parsing and validation limits. It examines responses for HTTP 400/431 (Header Fields Too Large), connection resets, or WAF blocks. The test covers cases such as very long `User-Agent` values, duplicated headers, extremely large cookie headers, and illegal characters in header names/values. Observed signals include header-related status codes, header truncation behavior, and server logs (if available). This probes whether front-end servers correctly limit header sizes, helping prevent header-based resource exhaustion and input-parsing vulnerabilities.

- [x] `sql_injection_test.py`

  Description:

  The SQL Injection probe sends a curated set of benign-but-malicious-looking payloads (URL parameters and POST bodies) that commonly appear in SQL injection attempts (e.g., `' OR '1'='1`, `UNION SELECT`, boolean condition probes). The purpose is not to exploit data; instead the test checks for server-side input validation, WAF triggers, or error-message leakage that indicates unsanitized database access. Measurements include WAF/403 hits, application error responses, and any database error content returned. Keep payloads non-destructive and ensure tests are run only on systems you control, because even harmless probes can trigger logging or protective responses.

- [ ] `protocol_confusion_test.py`

  Description:

  This test sends intentionally malformed HTTP requests — for example missing CRLF sequences, invalid HTTP methods, wrong protocol versions, or mixed-up chunk boundaries — to validate the server's protocol-compliance and parser robustness. It aims to discover how strictly the server enforces HTTP grammar and whether malformed inputs result in crashes, connection resets, or graceful 400/405 responses. The test records connection-level errors, abnormal process exits, and status codes. It is useful for catching parsers that behave unpredictably under malformed input and for ensuring the server fails safely.

- [ ] `malformed_request_test.py`

  Description:

  The Malformed Request test focuses on structurally invalid payloads and header/body mismatches (e.g., `Content-Length` not matching body size, chunked encoding errors, broken multipart boundaries). It checks whether the server properly validates incoming request framing and returns safe error responses rather than exposing stack traces or leaking internal state. Signals include 400-series responses, connection closes, and application error outputs. This test helps validate input validation layers, reverse proxy behavior, and application robustness against protocol framing anomalies.

- [ ] `auth_bruteforce_test.py`

  Description:

  The Auth Brute-Force test exercises authentication endpoints with low-rate credential trials to detect whether the server has account lockout, rate-limiting, or captcha defenses. The test sends configurable username/password combinations at controlled rates and records HTTP 200/401/429 responses and any account lock notifications. This test is intentionally rate-limited by default and should never be used against third-party services. It helps determine whether credential-guessing protections exist and whether additional mitigations (rate-limit per-IP, per-account lockout) are required.

- [ ] `directory_traversal_test.py`

  Description:

  The Directory Traversal test issues specially crafted path requests (e.g., `../`, encoded traversal sequences) and requests for known sensitive files to check for filesystem access leaks or incorrect path normalization. It verifies server and application-layer path sanitization and returns observations like 200 (sensitive file returned), 403 (forbidden), or 404 (not found). The test is non-destructive and should only request public or non-sensitive endpoints in practice. It helps find misconfigurations where static file handlers or application routing could expose filesystem contents.

- [ ] `tls_handshake_test.py`

  Description:

  The TLS Handshake test performs a range of TLS/SSL negotiation scenarios — different protocol versions, cipher suites, and malformed handshakes — to detect weak configurations and handshake robustness. It can check whether the server properly rejects obsolete TLS versions (e.g., SSLv3), offers only strong ciphers, and handles malformed client-hello sequences without crashing. Signals include successful negotiation with deprecated ciphers (bad), handshake failures (expected for disabled configs), and connection resets. This test assists in hardening TLS configuration and preventing downgrade or memory corruption issues in TLS stacks.

- [ ] `websocket_flood_test.py`

  Description:

  The WebSocket Flood test opens many concurrent WebSocket connections and/or sends high-frequency frames to test server support for real-time protocols. It checks for connection limits, frame-dropping, server memory growth, and any application-level backpressure handling. Observed signals include accepted connection counts, connection closures by server, and latency for echo/response frames. This test is useful when the server hosts WebSocket or other persistent real-time services and helps verify that per-connection resource caps and message throttling are in place.

- [ ] `resource_exhaustion_cpu_test.py`

  Description:

  The Resource Exhaustion (CPU) test triggers server-side expensive operations (safe, non-destructive inputs that cause heavy processing) to see whether CPU-intensive requests are protected by rate limits or cost-based throttling. Examples include requests that cause expensive regexes or large data parsing on the server. The test monitors response times, CPU usage (if available), and error patterns. Design inputs carefully — avoid destructive operations — and run in a controlled environment; the aim is to confirm that the server enforces limits to prevent a few expensive requests from degrading overall availability.

