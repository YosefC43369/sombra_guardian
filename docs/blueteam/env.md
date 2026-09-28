# Blue Team v0.8 environment variables

Defined in `blueteam/platform/config.py`, mirrored in `config.py::ENV_REGISTRY` and
`.env.example`. Every default is safe/off where it touches the network or shares
data; out-of-range values are clamped, not fatal.

| Variable | Default | Purpose |
|---|---|---|
| `BLUETEAM_V08_ENABLED` | `true` | Master switch. Off ⇒ all v0.8 modules dormant. |
| `BLUETEAM_V08_RETENTION_DAYS` | `180` | Retention for v0.8 time-series data. |
| `BLUETEAM_BATCH_FLUSH_S` | `2.0` | Write-behind batcher flush interval. |
| `BLUETEAM_INTEL_ENABLED` | `true` | Enable Threat Intel/IOC. |
| `BLUETEAM_INTEL_AUTO_MIN_CONF` | `75` | Min IOC confidence to auto-act (below ⇒ alert only). |
| `BLUETEAM_INTEL_MAX_IOCS` | `2000000` | Cap on IOCs per feed. |
| `BLUETEAM_INTEL_MAX_FEED_BYTES` | `104857600` | Cap on downloaded (compressed) bytes. |
| `BLUETEAM_INTEL_MAX_DECOMP_BYTES` | `524288000` | Cap after decompression (bomb guard). |
| `BLUETEAM_INTEL_MAX_DECOMP_RATIO` | `200` | Max expansion ratio (bomb guard). |
| `BLUETEAM_INTEL_GROWTH_RATIO` | `10.0` | Per-sync growth beyond this ⇒ quarantine. |
| `BLUETEAM_INTEL_FEED_TIMEOUT_S` | `30.0` | Feed fetch timeout. |
| `BLUETEAM_INTEL_BLOOM_CAP` | `5000000` | Bloom filter capacity. |
| `BLUETEAM_INTEL_LOOKUP_CACHE` | `50000` | Lookup LRU size. |
| `BLUETEAM_INTEL_SYNC_INTERVAL_S` | `3600` | Feed auto-sync interval (opportunistic). |
| `BLUETEAM_INTEL_ABUSECH_AUTHKEY` | *(empty)* | abuse.ch Auth-Key; empty ⇒ feeds needing it stay off. |
| `BLUETEAM_DAC_ENABLED` | `true` | Enable Detection-as-Code. |
| `BLUETEAM_DAC_MAX_RULES` | `2000` | Max rules. |
| `BLUETEAM_DAC_MAX_NODES` | `500` | Condition AST node budget. |
| `BLUETEAM_DAC_MAX_REGEX_LEN` | `500` | Max rule-regex length. |
| `BLUETEAM_DAC_MAX_WINDOW_S` | `3600` | Max aggregation window. |
| `BLUETEAM_DAC_RULE_BUDGET_US` | `2000` | Per-rule time budget per message (µs). |
| `BLUETEAM_DAC_SLOW_TRIPS` | `5` | Slow-rule strikes before circuit-breaking. |
| `BLUETEAM_POSTURE_ENABLED` | `true` | Enable Security Posture. |
| `BLUETEAM_POSTURE_ROLLUP_S` | `3600` | Rollup bucket size. |
| `BLUETEAM_POSTURE_SNAPSHOT_S` | `86400` | Snapshot interval (opportunistic). |
| `BLUETEAM_POSTURE_DROP_ALERT` | `10.0` | Emit `posture.score_dropped` on a drop ≥ this. |

## Notes
- Feed URLs must be `https` and pass the SSRF guard. A feed with an uncertain
  license ships `license_ok=false` / disabled and requires explicit operator opt-in.
- Egress is opt-in and off by default; message content never leaves the system.
