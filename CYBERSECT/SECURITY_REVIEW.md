# CYBERSECT Security Review and Response Playbooks

## Scope and current architecture

The reviewed runtime is `app.main`, which installs `ProxySecuritySensor` and serves the
dashboard on loopback through `run_local.sh`. It includes bounded private-subnet
discovery, optional credentialed SSH/SMB inventory, and an operator-run endpoint hash
agent. The files `air_ds_gateway.py`,
`air_ds_multisensor_gateway.py`, and `hardened_gateway.py` define separate FastAPI apps;
they are not composed into the main application. Treat those apps as standalone examples,
not as controls protecting the dashboard.

This is a repository-level code review, not a penetration test, certification, or claim of
readiness for classified or regulated production systems. The active deployment described
by the README listens on `127.0.0.1`; the conclusions change if it is exposed through a
proxy, container, or network interface.

## Findings

1. **Remote sensor identity and replay protection are not implemented (High if exposed
   beyond the local host).** The active API authenticates with one shared API key. It has
   no sensor-specific identities or mTLS. Critical alerts require an HMAC over only the
   target asset and severity; the signature has no timestamp or nonce, so it can be
   replayed. The alert endpoint records an incident and returns a recommendation; it does
   not isolate a host. Keep the service loopback-only until a deployment design supplies
   authenticated service identities, rotation, replay checks, and transport protection.

2. **The proxy sensor has bounded but potentially expensive request inspection (Medium).**
   `ProxySecuritySensor` buffers up to 17 MiB and 2,048 ASGI body messages, decodes
   text, checks fixed signatures, and hashes blocked requests. The reviewed patterns do not
   show the nested ambiguous repetition commonly associated with catastrophic regex
   backtracking, so a specific ReDoS defect was not confirmed. Large or slowly delivered
   bodies can still consume memory, CPU, and worker time when requests arrive concurrently.
   Add server/reverse-proxy timeouts, connection limits, and measured resource budgets
   before network exposure.

3. **There is no horizontal shared state or rate limiter (Medium for multi-worker use).
   ** SQLite serializes writes with a five-second busy timeout. Incident and raw telemetry
   buffers are process-local lists, while geolocation results are process-local caches.
   Multiple workers or hosts therefore do not share those buffers or caches, and the
   `REQUEST_COUNTS` variable in the standalone hardened gateway is not a rate limiter.
   Use a shared store and explicit per-client limits if scaling beyond one local process.

4. **Security history is not immutable (High where audit retention is required).**
   `attack_events` is SQLite-backed and deletes older events above 10,000 rows. Raw
   telemetry and incidents are in-memory and capped, and disappear on restart. Request
   fingerprints are useful for correlation but do not form a verified hash chain. This is
   not WORM storage or tamper-evident audit logging.

5. **The SQLite analyzer is schema analysis, not SQL-injection analysis.**
   `database_static_analyzer.py` opens an uploaded snapshot read-only and inspects schema
   metadata without returning rows or executing stored SQL. An AST parser such as SQLGlot
   would be relevant only if the product accepts or analyzes SQL statements; it is not a
   substitute for parameterized queries in code that executes SQL.

6. **The active anomaly endpoint is not an AI model.** `/api/v1/detect/dnn-anomaly` uses a
   weighted threshold formula. The PyTorch autoencoder is not loaded and has no trained
   weights in this API, so adversarial ML hardening is not currently the primary risk.
   Calibrate the threshold against representative telemetry before using it to drive
   containment.

7. **Malware checks are indicators, not a sandbox.** Upload scanning checks local SHA-256
   indicators and a few static byte patterns. Unknown files are not proven clean and are
   never executed for analysis. The active route and the standalone gateway routes now
   enforce a 2 MiB read limit; these checks still do not replace isolated detonation or
   endpoint protection.

8. **No public stack trace disclosure was found in the active API paths reviewed.** Most
   handled database errors return generic HTTP details, while `LOGGER.exception` keeps
   diagnostics in server logs. Keep those logs access-controlled and avoid forwarding raw
   tracebacks or secrets to telemetry consumers.

9. **Browser API access is broadly configured.** The active app enables CORS for any
   origin, although cookie credentials are disabled and protected routes require the API
   key. Same-origin dashboard use does not require broad CORS; deployments that need a
   separate browser client should configure an explicit origin allowlist.

10. **Several legacy messages overstated response actions.** The standalone gateway code
    previously logged that it had blocked an IP, terminated a session, or executed a
    playbook when it only returned HTTP 403. Those messages now state the actual behavior.
    The standalone hardened gateway also now compares API keys with `hmac.compare_digest`.

11. **Scanner scope remains intentionally limited.** Network discovery accepts only
    loopback/private/ULA targets and at most 256 addresses, over an allowlist of eight TCP
    ports. The built-in path performs connects, banners, SMB negotiate, and HTTP HEAD
    checks. An optional Nmap path runs service-version checks and a fixed packaged safe
    script allowlist, with OS fingerprinting when raw-socket privileges are available.
    Neither path runs exploit, brute-force, intrusive, or arbitrary user-supplied plugins.
    Credentialed SSH requires a local key and strict known-host validation; SMB uses a
    temporary credential file and lists shares over SMB3. The endpoint agent hashes only
    explicitly selected roots and compares a local baseline; hash matches depend on
    imported catalog data, while baseline-change alerts are heuristic. Reports are not
    signed, so host identity and contents are not independently attested. No feature
    isolates, locks, deletes, or otherwise changes a target.

## Recommended implementation order

1. Keep the current service loopback-only. Before remote deployment, add per-sensor
   certificates from a managed CA, mTLS verification, short-lived credentials, and
   timestamp/nonce replay rejection. Use hardware-backed keys only where the operating
   environment supports and manages TPM/HSM enrollment and recovery.
2. Restrict CORS to named browser origins when cross-origin access is required. Add
   reverse-proxy request deadlines, maximum concurrent requests, rate limits, and
   independent worker resource limits.
3. Move security events to a shared append-only audit service. If a local hash chain is
   added, specify key management, checkpoint signing, rotation, retention, and external
   verification; a hash chain in the same writable SQLite file is not WORM protection.
4. Keep SQL analysis separate from schema analysis. For any future SQL ingestion feature,
   parse statements with a dialect-aware AST and still enforce parameterized execution,
   authorization, and query time/resource limits.
5. Add a fuzzing job for parsers and bounded input handling in CI. AFL++ is most useful
   with a native parser harness; Python HTTP request handling should also receive
   property-based and mutation fuzzing with strict body and time budgets.
6. Do not add PQC or automated host isolation as a label-only feature. ML-KEM-1024 and
   SLH-DSA require a reviewed protocol, supported cryptographic libraries, key lifecycle,
   interoperability tests, and a deployment threat model. Isolation, account locking,
   forensic capture, and failover require explicit integrations and rollback procedures.

## Incident response playbooks

The current product can record alerts and return recommendations. It does not revoke
sessions, lock accounts, quarantine nodes, reroute sensors, capture memory, or write to
WORM storage. Until those integrations exist, operators must treat the actions below as
procedures and recommendations, not automated capabilities.

### 1. Sensor anomaly or suspected node spoofing

- **Trigger:** Sensor identity/certificate validation failure, replay-window violation,
  or a telemetry deviation confirmed against an independent source.
- **Validate:** Confirm the sensor ID, certificate serial, event timestamp, nonce status,
  source network, recent enrollment/rotation, and whether a maintenance window explains
  the change. Preserve the original telemetry and relevant gateway logs.
- **Contain:** Notify the on-call security lead. Disable the sensor credential or isolate
  the node through the managed network/orchestration control only after the authorized
  operator approves. Fail over only to a known-good sensor and mark any telemetry gap.
- **Recover:** Re-enroll or rebuild the node, rotate its credential, verify clock
  synchronization and duplicate/replay rejection, then restore traffic gradually.
- **Record:** Store the decision, evidence hashes, approver, containment time, and recovery
  validation in the organization’s protected audit system.

### 2. WAF overload or suspected DoS/ReDoS

- **Trigger:** CPU above 90% for a sustained interval, rising request-processing latency,
  worker saturation, or repeated expensive inspection events. A single CPU sample is not
  sufficient evidence for automatic blocking.
- **Validate:** Compare request rate, body sizes, chunk counts, route, latency percentiles,
  and upstream health. Capture bounded metadata and fingerprints; do not retain request
  bodies or credentials by default.
- **Contain:** Apply rate and connection limits at the trusted edge, reject oversized or
  expired requests, and reduce traffic to affected routes. Choose fail-closed behavior per
  route based on a documented availability/security policy; do not silently switch modes
  after a sensor exception.
- **Recover:** Remove temporary limits in stages after CPU and latency return to baseline;
  test benign traffic and inspect missed/blocked event counts.
- **Record:** Link mitigation changes to an incident ID and retain thresholds, timing, and
  approval in the audit system.

### 3. Suspected account abuse or database privilege misuse

- **Trigger:** Authentication anomalies, unexpected role/privilege changes, unusual
  query volume, or verified attempts to access unauthorized records.
- **Validate:** Correlate identity-provider, application, database, and endpoint logs.
  Preserve database WAL/journal files and relevant logs without querying or exporting
  unrelated sensitive rows.
- **Contain:** Revoke sessions and disable the account through the identity provider after
  incident lead approval. Rotate affected service credentials and restrict the database
  principal. Do not lock accounts or take forensic snapshots solely from an unverified
  pattern match.
- **Recover:** Rebuild credentials from the approved secret manager, review grants, restore
  from a verified backup if integrity was affected, and monitor for repeat access.
- **Record:** Place evidence in approved immutable storage with custody metadata, hashes,
  collector, timestamps, and access history. Memory capture requires an approved endpoint
  forensic tool and legal/operational authorization.

## Validation performed

- Syntax compilation in Arch WSL: **passed**.
- Existing pytest suite in Arch WSL after the edits: **40 passed**. Its environment emits a Starlette
  deprecation warning because the installed Starlette test client falls back to `httpx`;
  this does not affect the application’s HTTP client or indicate a failing test.
