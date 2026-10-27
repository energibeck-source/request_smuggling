# request_smuggling — technique backlog

Techniques found in the research below that are **missing** from the current tool.
Current modules: `clte, tecl, tete (classic), 0cl (0.CL), h2te, h2cl_ignore (H2.CL), h2crlf`.

Sources read 2026-10-19:
- HTTP/1 Must Die — https://portswigger.net/research/http1-must-die
- Browser-Powered Desync (2022) — https://portswigger.net/research/browser-powered-desync-attacks
- TE.0 (2024, Google Cloud) — https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/
- Funky chunks (2025) — https://w4ke.info/2025/06/18/funky-chunks.html

---

## Missing desync classes (detection modules)

- [x] **CL.0** — back-end ignores Content-Length, treats body as zero-length; the body bytes start the next request. Distinct from the 0.CL I already have (that's the front-end ignoring CL). Detect: POST with oversized CL + a second request on the same connection. DONE 2026-10-27: `modules/clzero.go` (tech `cl0`), payloads `BuildCLZero`/`BuildNormalGet`, on `SimpleRequester.SendRawPipelined`. Signal = >2 responses for 2 pipelined requests (smuggled marker surfaces as own response).

- [x] **TE.0** — back-end ignores Transfer-Encoding, treats the chunked body as empty (the "CL.0 of chunked"). Google Cloud LB bug. Probe with **OPTIONS** (GET/POST failed in their tests), `Transfer-Encoding: chunked`, smuggled request in the chunk, no self-added Content-Length. DONE 2026-10-27: `modules/tezero.go` (tech `te0`), payload `BuildTEZero` on `SendRawPipelined`. Fragment-safe (dangling X-Ignore, no queue poisoning). NOTE: payload contract + safety verified by test; full front/back TE.0 behavior needs a real target — not yet hit in the wild.

- [x] **H2.0** — HTTP/2 variant of CL.0: an HTTP/2 request carrying content-length is ignored by the back-end after downgrade. Same two-request test as CL.0. Seen on amazon.com `/b/`. DONE 2026-10-27: `modules/h2zero.go` (tech `h20`). Needed a new h2 primitive — `h2raw.Client.WriteRequest` (send stream, no read) + `DrainResponses` (stream-aware, one HPACK decoder per conn). Two streams (1=poison POST+content-length+dangling body, 3=normal GET); signal = stream 3 swallowed/RST/GOAWAY (High) or status diverges from baseline (Medium). Primitive verified end-to-end on a real h2 server; full front/back H2.0 desync needs a live target.

- [x] **Chunk-extension desync (TERM.EXT / EXT.TERM)** — not my classic header-obfuscation TE.TE. Parser disagreement on a bare-LF inside a chunk extension (`2;` + bare `\n`). TERM.EXT = proxy ends header at LF, server treats LF as extension; EXT.TERM = reverse. Timeout-based probe. Ref scanner: `smugchunks`. DONE 2026-10-27: `modules/chunkext.go` (tech `chunkext`), payloads `BuildChunkExtTermExt`/`BuildChunkExtExtTerm` (bare LF after `size;x`). Timing detection via `SendRawProbe` + `CheckTimeout`, same as CLTE; two orientations sent so a timeout on one reveals TERM.EXT vs EXT.TERM. Sim-verified: hang→finding, clean→no FP. Exact hang-inducing byte framing should be confirmed against a real front/back pair.

- [x] **Expect-based desync** — abuse `Expect: 100-continue`. Four forms: vanilla + obfuscated, each with CL.0 and 0.CL variants. Also enables a second response-header block to bypass proxy header-stripping. DONE 2026-10-27: `modules/expect.go` (tech `expect`), payload `BuildExpectHeadersAndBody` on `SendRawWithDelay` (send headers, pause, observe pre-body bytes). Classifies 3 runs (none/plain/obfuscated): double header-block 100+final before body (High, header-strip bypass), early final on Expect only (Medium, early-response gadget for 0.CL), obfuscated-vs-plain disagreement (Medium). Sim-verified all 3 branches + no-FP on a 100-continue-honoring server. TODO-next: the explicit CL.0/0.CL-with-Expect smuggle variants (body-hold reparse) on top of this.

- [ ] **Bare-LF header termination** — server accepts a lone `\n` as a line terminator; exploitable behind a proxy that requires CRLF. Add as a header-obfuscation permutation across modules.

## Missing client/connection-level attacks

- [ ] **Client-side desync (CSD)** — browser-driven: victim's two cross-domain `fetch()` calls, first poisons the browser connection pool, second gets the malicious response. Confirm by shared Connection ID in-browser. (Needs a browser-side PoC generator, not just raw sockets.)

- [ ] **Pause-based desync** — send headers promising a body, then pause; server times out but keeps the connection, parses the unsent body as a new request. Works against streaming front-ends (Varnish, Apache behind ALB).

- [x] **Connection-state attacks** — server assumes all requests on one connection share the first request's Host/validation. Two exploits: first-request validation bypass (reach internal sites) and first-request routing (reach any back-end). HTTP Request Smuggler has a "connection-state probe". DONE 2026-10-27: `modules/connstate.go` (tech `connstate`), payload `BuildHostProbe`, on `SendRawPipelined`. Sends a bad-Host probe standalone vs primed-as-2nd-request; divergence = front validates/routes only the first request (High when blocked-standalone→served-primed). Fully sim-verified (vuln vs safe front, no FP). Set `AltHost` to a real internal vhost to escalate to impact.

## Missing exploitation primitives (turn detections into impact)

- [ ] **Early-response gadget finder** — endpoints that reply before the body (IIS `/con`, server-level redirects). Required to break the 0.CL deadlock; pair with my existing 0cl/timebased_0cl.

- [ ] **Double-desync chain** — stage 1 poisons the connection with 0.CL, stage 2 flips it into a CL.0 carrying the malicious prefix. The full 0.CL exploit path from the paper.

- [ ] **Response Queue Poisoning (RQP)** — split one request into two complete back-end requests so responses misalign and users receive each other's responses.

- [ ] **HEAD framing technique** — HEAD to a path so back-end response framing misaligns, letting attacker-served content through.

- [ ] **Method switching** — swap to OPTIONS/other to get past front-ends that reject bodies on GET (also the key that made TE.0 fire).

## Missing detection upgrades

- [ ] **CL-based discrepancy detection** — Daniel Thacher's approach (HTTP Request Smuggler v3.0): compare responses to differently-malformed requests. More WAF-resistant than my timing-based detection.

- [ ] **Mystery-400 heuristic** — flag unexplained 400s as candidate 0.CL.

- [ ] **Offset finder** — measure how many bytes of injected headers the front-end appends (cf. Turbo Intruder `0cl-find-offset.py`). Needed to size 0.CL/double-desync payloads.

- [~] **Header-permutation + strategy matrix** — combine permutations (leading space, etc.) with strategies (duplicate Host with invalid value) instead of fixed probes. ENGINE DONE 2026-10-27: `payloads/mutations.go` (registry `HeaderMutations` + `BuildHeaderMatrixProbe`), `modules/headermatrix.go` (tech `headermatrix`). Permutation axis = 6 mutations (canonical control + space-before-colon, tab-separator, obs-fold, bare-lf, leading-space-name); oracle axis = reflection only so far (unique marker echoed in a response header=High / body=Medium; canonical excluded as baseline). Attacks Host + X-Forwarded-Host by default. Sim-verified: obfuscated reflections flagged, canonical excluded, no-echo→no FP. STILL TODO: more oracles (routing, validation-bypass, timing), `-tech` sub-selection of individual mutations, reconnect TE.TE/ConnState to this registry. Which mutations actually split a given front/back is a live-target question.

---

Notes:
- 2004 (cgisecurity) and 2016 (Hiding Wookiees) not deep-read — their advances (classic smuggling, header obfuscation) are already covered by clte/tecl/tete.
- CSD and pause-based (client-side half) need a browser/MITM harness, bigger than a raw-socket module — scope separately.
