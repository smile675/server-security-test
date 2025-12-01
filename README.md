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
python flood_resistance_test.py https://yourdomain.com --concurrency 50 --duration 20
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
python slow_client_test.py https://yourdomain.com --concurrency 10 --duration 15 --delay 2.0
```

**Arguments:**
- `--concurrency` (int, default 10): Number of parallel slow clients
- `--duration` (int, default 10): Test duration in seconds
- `--delay` (float, default 2.0): Delay between payload chunks in seconds

# Contribution Guide

If you would like to contribute to this project, please follow the [Contribution Guide](CONTRIBUTING.md) for instructions on how to contribute effectively.
