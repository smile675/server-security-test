#!/usr/bin/env python3
import argparse
import socket
import time
from collections import defaultdict


# Malformed HTTP request patterns
MALFORMED_REQUESTS = [
    # Missing CRLF (just LF)
    b"GET / HTTP/1.1\nHost: example.com\n\n",
    
    # Invalid HTTP method
    b"INVALID / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    
    # Missing HTTP version
    b"GET /\r\nHost: example.com\r\n\r\n",
    
    # Invalid HTTP version
    b"GET / HTTP/2.5\r\nHost: example.com\r\n\r\n",
    
    # Spaces instead of tabs in request line
    b"GET  /  HTTP/1.1\r\nHost: example.com\r\n\r\n",
    
    # Missing colon in header
    b"GET / HTTP/1.1\r\nHost example.com\r\n\r\n",
    
    # Duplicate content-length headers with conflicting values
    b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello",
    
    # Invalid chunked encoding (missing size)
    b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n\r\nhello\r\n0\r\n\r\n",
    
    # Chunk size not in hex
    b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nhello\r\n0\r\n\r\n",
    
    # Content-Length with negative value
    b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: -5\r\n\r\nhello",
    
    # Oversized Content-Length header value
    b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999999999999999999\r\n\r\nhello",
    
    # Mixed line endings (CR only, no LF)
    b"GET / HTTP/1.1\rHost: example.com\r\r",
    
    # Null byte in request line
    b"GET / HTTP/1.1\x00\r\nHost: example.com\r\n\r\n",
    
    # Very long header value (potential buffer overflow)
    b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: " + b"A" * 10000 + b"\r\n\r\n",
    
    # Invalid URI characters
    b"GET /\x01\x02\x03 HTTP/1.1\r\nHost: example.com\r\n\r\n",
]


def send_malformed_request(host, port, request_bytes, timeout=5):
    """
    Send a malformed HTTP request and record the response.
    Returns: (status, response_bytes, exception_type)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request_bytes)
        
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        
        sock.close()
        
        # Try to parse response
        if response:
            # Extract status line
            lines = response.split(b"\r\n")
            if lines and lines[0]:
                status_line = lines[0].decode('utf-8', errors='ignore')
                return ("response", status_line, None)
        
        return ("no_response", "", None)
    
    except socket.timeout:
        return ("timeout", "", "timeout")
    except ConnectionRefusedError:
        return ("connection_refused", "", "connection_refused")
    except ConnectionResetError:
        return ("connection_reset", "", "connection_reset")
    except BrokenPipeError:
        return ("broken_pipe", "", "broken_pipe")
    except Exception as e:
        return ("exception", "", type(e).__name__)
    
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_test(host, port, duration=None, scheme="http"):
    print("\nStarting Protocol Confusion Test")
    print(f"Target: {scheme}://{host}:{port}")
    print(f"Malformed request patterns: {len(MALFORMED_REQUESTS)}")
    print("------------------------------------\n")
    
    results = {
        "total_sent": 0,
        "response": defaultdict(int),
        "timeout": 0,
        "connection_refused": 0,
        "connection_reset": 0,
        "broken_pipe": 0,
        "exception": defaultdict(int),
        "response_lines": [],
        "latencies": [],
    }
    
    # Cycle through requests
    request_index = 0
    start_time = time.time()
    
    while True:
        # Check duration
        if duration and (time.time() - start_time) > duration:
            break
        
        request_bytes = MALFORMED_REQUESTS[request_index % len(MALFORMED_REQUESTS)]
        request_index += 1
        
        req_start = time.perf_counter()
        status, response_line, exception = send_malformed_request(host, port, request_bytes)
        latency = time.perf_counter() - req_start
        
        results["total_sent"] += 1
        results["latencies"].append(latency)
        
        if status == "response":
            results["response"][response_line] += 1
            results["response_lines"].append(response_line)
        elif status == "timeout":
            results["timeout"] += 1
        elif status == "connection_refused":
            results["connection_refused"] += 1
        elif status == "connection_reset":
            results["connection_reset"] += 1
        elif status == "broken_pipe":
            results["broken_pipe"] += 1
        elif status == "exception":
            results["exception"][exception] += 1
        
        time.sleep(0.1)  # Small delay between requests
    
    # Summary
    print("\n====== RAW RESULT DATA ======")
    print(f"Total malformed requests sent: {results['total_sent']}")
    print(f"\nResponse outcomes:")
    print(f"  Received HTTP response: {len(results['response'])}")
    print(f"  Connection timeout: {results['timeout']}")
    print(f"  Connection refused: {results['connection_refused']}")
    print(f"  Connection reset by peer: {results['connection_reset']}")
    print(f"  Broken pipe: {results['broken_pipe']}")
    print(f"  Other exceptions: {dict(results['exception'])}")
    
    if results["response_lines"]:
        print(f"\nHTTP Status lines observed (first 10):")
        for line in results["response_lines"][:10]:
            print(f"  - {line}")
    
    if results["latencies"]:
        avg_lat = sum(results["latencies"]) / len(results["latencies"])
        min_lat = min(results["latencies"])
        max_lat = max(results["latencies"])
        print(f"\nLatency stats:")
        print(f"  Average: {avg_lat:.4f}s")
        print(f"  Min: {min_lat:.4f}s")
        print(f"  Max: {max_lat:.4f}s")
    
    # Protection analysis
    print("\n====== PROTECTION ANALYSIS ======")
    protected = False
    vulnerable = False
    
    if results["connection_reset"] > 0:
        print(f"Server reset {results['connection_reset']} malformed connections — parser robustness detected.")
        protected = True
    
    status_codes = set()
    for line in results["response_lines"]:
        if "400" in line:
            status_codes.add("400")
            protected = True
        if "405" in line:
            status_codes.add("405")
            protected = True
        if "500" in line:
            status_codes.add("500")
            vulnerable = True
    
    if status_codes:
        print(f"HTTP status codes: {', '.join(sorted(status_codes))}")
    
    if "400" in status_codes or "405" in status_codes:
        print("Server gracefully rejected malformed HTTP with 4xx errors.")
        protected = True
    
    if "500" in status_codes:
        print("Server returned 5xx errors for malformed input (possible internal errors).")
        vulnerable = True
    
    if results["connection_refused"] > 0:
        print(f"Server refused connections ({results['connection_refused']}x) — may indicate overload or strict parsing.")
    
    if results["timeout"] > 0:
        print(f"Timeouts occurred ({results['timeout']}x) — server may hang on malformed input.")
        vulnerable = True
    
    if results["exception"]:
        print(f"Client-side exceptions: {dict(results['exception'])}")
        if "connection_reset" not in results["exception"]:
            protected = True
    
    print("\n====== FINAL VERDICT ======")
    if vulnerable and not protected:
        print("WARNING: Server may be VULNERABLE to protocol confusion attacks.")
        print("Timeouts, crashes, or internal errors detected. Review HTTP parser configuration.")
    elif protected:
        print("Server shows good protocol compliance: rejects malformed input gracefully.")
    else:
        print("No clear signals detected. Results inconclusive.")
        print("Consider: are malformed requests being silently dropped, or is parser too lenient?")
    
    print("============================\n")


def protocol_confusion_test():
    parser = argparse.ArgumentParser(
        description="Test server protocol compliance and robustness against malformed HTTP requests"
    )
    parser.add_argument("host", help="Target host (e.g., yourdomain.com)")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80 for HTTP, 443 for HTTPS)")
    parser.add_argument("--scheme", type=str, default="http", choices=["http", "https"], help="Scheme (http or https)")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    
    args = parser.parse_args()
    
    # Adjust default port if https
    if args.scheme == "https" and args.port == 80:
        args.port = 443
    
    run_test(args.host, args.port, args.duration, args.scheme)


if __name__ == "__main__":
    protocol_confusion_test()
