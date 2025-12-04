# Attacks → Nginx Config Snippets

This file maps common attack types (the tests under `tests/`) to the minimal, exact nginx lines or blocks you can add to your configuration to mitigate them. Keep the lines in the context noted (http / server / location). Be concise; these are minimal, practical mitigations — tune numeric values to match your traffic.

---

Attack name: Flood / High Request Rate

defence configuration in nginx setup:
- Add to `http {}` (global zone):

```nginx
limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
```

- Add to the `server {}` or a `location / {}` where you want to enforce it:

```nginx
limit_req zone=req_limit_per_ip burst=20 nodelay;
limit_conn conn_limit_per_ip 10;  # max concurrent connections per IP
```

Place: `limit_req_zone` / `limit_conn_zone` in the `http` block; `limit_req` / `limit_conn` inside `server` or `location`.

---

Attack name: Slow Client (Slowloris-style)

defence configuration in nginx setup:
- Reduce timeouts and enable buffering (in `server`):

```nginx
client_header_timeout 30s;
client_body_timeout 30s;
send_timeout 15s;
proxy_request_buffering on;  # buffer request body before sending upstream
```

- Optionally limit connections per IP (see Flood snippet) so slow clients can't exhaust slots.

Place: `server {}` or global `http {}` depending on scope.

---

Attack name: Large Payload / Upload Abuse

defence configuration in nginx setup:
- Set max allowed body size (in `server` or `location`):

```nginx
client_max_body_size 20M;
client_body_buffer_size 128k;
```

- If you need to reject large uploads immediately, use `client_max_body_size` in `location` handling uploads.

Place: `server` or specific `location` that receives uploads.

---

Attack name: Header Injection / Oversized Headers

defence configuration in nginx setup:
- Increase header buffer limits and fail large headers (in `http`):

```nginx
client_header_buffer_size 4k;
large_client_header_buffers 4 16k;
```

- Add blocking for suspicious UAs (simple):

```nginx
map $http_user_agent $bad_ua {
  default 0;
  ~*(?:sqlmap|nikto|acunetix|masscan|python-requests) 1;
}

server {
  if ($bad_ua) { return 403; }
}
```

Place: buffers in `http`; `map` in `http`; `if ($bad_ua)` in `server`.

---

Attack name: SQL Injection (detection / WAF)

defence configuration in nginx setup:
- Nginx alone cannot reliably block SQLi; use ModSecurity / WAF. Minimal nginx lines to integrate ModSecurity:

```nginx
# inside http or server (requires ModSecurity installed)
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

- If you cannot run ModSecurity, use rate-limiting and input-size limits (see Flood and Large Payload snippets) and block known scanner UAs.

Place: `server` or `http` (depends on module installation).

---

Attack name: Protocol Confusion / Malformed HTTP (missing CRLF, invalid methods)

defence configuration in nginx setup:
- Reject unexpected methods quickly and enforce timeouts:

```nginx
if ($request_method !~ ^(GET|POST|HEAD|PUT|DELETE|OPTIONS)$) {
  return 405;
}
client_body_timeout 10s;
client_header_timeout 10s;
```

- Use raw socket protections (Nginx will return 400 for bad requests in most cases). Use error logs to tune.

Place: `server {}`.

---

Attack name: Malformed Request Framing (Content-Length mismatch, chunked errors)

defence configuration in nginx setup:
- Tighten timeouts and reduce buffers to avoid parser hang:

```nginx
client_body_timeout 10s;
client_header_timeout 10s;
large_client_header_buffers 4 16k;
client_max_body_size 20M;
```

- Consider enabling ModSecurity to detect malformed framing and return 400/close connection.

Place: `server` or `http`.

---

Attack name: Auth Brute-Force

defence configuration in nginx setup:
- Create a dedicated slow zone and enforce it on auth endpoints (zone declared in `http`):

```nginx
# http block (once):
limit_req_zone $binary_remote_addr zone=req_limit_login:10m rate=1r/s;

# in server/location for login:
limit_req zone=req_limit_login burst=5 nodelay;
limit_conn conn_limit_per_ip 3;   # optional
```

Place: `limit_req_zone` in `http`; `limit_req` / `limit_conn` inside the auth `location`.

---

Attack name: Directory Traversal / Sensitive File Discovery

defence configuration in nginx setup:
- Deny access to common sensitive filenames and block traversal patterns:

```nginx
# in http:
map $request_uri $bad_uri {
  default 0;
  ~*(?:\.\./|/etc/passwd|/\.git/|\.env|wp-config\.php) 1;
}

# in server:
if ($bad_uri) { return 404; }

# deny direct access to sensitive filenames
location ~* (?:\.env|\.git|wp-config\.php|web\.config)$ {
  deny all;
  access_log off;
}
```

Place: `map` in `http`, `if` and `location` in `server`.

---

Attack name: TLS Handshake / Weak TLS

defence configuration in nginx setup:
- Enforce modern TLS and strong ciphers (in `server` TLS config):

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:...:ECDHE-RSA-AES128-GCM-SHA256";
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

- For full hardening, run an external TLS test (SSL Labs) and tune `ssl_ciphers` accordingly.

Place: inside `server` TLS block.

---

Attack name: WebSocket Flood / Many Persistent Connections

defence configuration in nginx setup:
- Limit connections + ensure Nginx proxies websocket correctly; enable per-IP conn limits and increase worker limits globally:

```nginx
# http (global)
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
worker_connections 2048;

# in server or location for ws endpoint
limit_conn conn_limit_per_ip 20;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "Upgrade";
proxy_read_timeout 60s;
```

Place: `limit_conn_zone` in `http`, `limit_conn` and ws proxy settings in `location` handling WS.

---

Attack name: Resource Exhaustion (CPU heavy requests)

defence configuration in nginx setup:
- Use rate-limiting, timeouts, request-size limits, and prefer graceful throttling:

```nginx
limit_req zone=req_limit_per_ip burst=10 nodelay;
client_max_body_size 20M;
proxy_read_timeout 30s;
# track slow responses via logs and add 429 responses if needed
```

- Complement with ModSecurity/OWASP CRS and application-side cost limits (e.g., input validation, expensive-operation caps).

Place: `server` or specific `location` for the endpoint under test.

---

Notes & recommended additions
- For content inspection and stronger WAF rules, install ModSecurity (recommended) and enable OWASP CRS. Example minimal lines (requires ModSecurity compiled and module enabled):

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

- Always test changes on staging first. Tune `rate`, `burst`, `conn` values to match real traffic.
- Use logging (`access_log`, `error_log`) and monitoring to verify whether the rule triggers false positives.
