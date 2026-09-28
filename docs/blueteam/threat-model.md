# Blue Team v0.8 threat model (STRIDE)

Scope: the v0.8 modules and their data. The bot ingests **external feed data** and
**user messages**, both treated as untrusted **data, never commands**.

## Assets
- The IOC index and feed state; detection rules and their version history;
  posture snapshots/reports; the integrity ledger; per-tenant isolation.

## STRIDE

### Spoofing
- **Feed impersonation / poisoning.** Feeds are `https`-only and pass the SSRF
  guard. A poisoning guard whitelists high-reputation registrable domains and
  quarantines a sync whose item count balloons (`growth_quarantine_ratio`). Feeds
  with uncertain licenses ship disabled.
- **Fake admin commands.** Global/write commands require OWNER (a chat admin of the
  group's own single-group tenant); reads require ADMIN. Membership is re-checked
  via the Bot API at call time.

### Tampering
- **Rule tampering.** Rule bodies are versioned in a **hash chain**
  (`sha256(prev || canonical(body))`), verifiable with `/rule history`; each change
  is also sealed to the Merkle integrity ledger.
- **Report tampering.** Every report's SHA-256 is stored and sealed; `/posture
  verify` re-hashes a supplied report and compares.
- **SQL tampering.** All queries are parameterized; tables are `bt_`-prefixed.

### Repudiation
- Lifecycle changes and reports are sealed to the append-only integrity ledger
  (best-effort; self-disables cleanly if the ledger is unavailable).

### Information disclosure
- **No live IOCs in events/logs.** `intel.ioc_matched` carries only a defanged value
  and a hash subject. Command output defangs URLs/domains/IPs.
- **Client report profile** pseudonymizes group ids and drops internal notes.
- **Tenant isolation.** Repository reads are scoped by `chat_id`/tenant; a single
  group is its own tenant. Data never crosses groups.
- **Egress is opt-in and off by default.** No message content leaves the system.

### Denial of service
- **ReDoS.** Rule regex is linted (nested-quantifier reject, length cap) and compiled
  once; a slow rule is circuit-broken.
- **Decompression bombs.** Feed gzip/zip is expanded under an absolute size cap and a
  max expansion ratio; over-limit quarantines the sync.
- **Rule complexity.** Condition AST node count is bounded; aggregation windows are
  bounded ring buffers; the lookup index is memory-bounded (Bloom capacity, caps).
- **Message-path safety.** Analysis is fail-open and time-bounded per rule.

### Elevation of privilege
- **No `eval`/`exec`/`compile`** on rule data (ADR 0004) — rule import cannot execute
  code. The Sigma-lite grammar is the security boundary.
- **SSRF.** Feed fetches resolve + screen the host (reject private/loopback/metadata/
  CGNAT) and re-resolve immediately before connecting (rebind mitigation).

## Explicitly out of scope / not claimed
Facts the Telegram Bot API cannot observe are never asserted (admin 2FA status,
member IP addresses, device posture). Posture controls map only to observable state.
