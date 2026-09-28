# Blue Team v0.8 known limitations

- **Observability boundary.** Detection uses only what the Telegram Bot API and the
  bot's own state expose. It cannot see admin 2FA, member IP addresses, device
  posture, or content in other apps — and never claims to. Posture controls map only
  to observable facts.
- **Passive/defensive only.** No offensive capability. Intel is lookup/scoring;
  detections raise events; response actions belong to the existing guard modules and
  admin workflows.
- **Feeds need reachability + license.** Feeds are `https`-only through the SSRF
  guard, so an environment that blocks outbound HTTPS has no feed data (local IOCs
  still work). abuse.ch feeds may require a free Auth-Key; without it they stay off.
  Feeds with uncertain licenses ship disabled and need explicit opt-in.
- **Opportunistic scheduling.** With no platform background-task hook, feed sync and
  posture snapshots are driven off message activity (throttled, in an executor). A
  completely silent group won't sync until a message arrives or a command runs. A
  future platform scheduler hook (the `JobStore`/`Scheduler` port already exists)
  would make this time-driven.
- **Rollup granularity.** Posture trend is hourly-bucketed (running mean); sub-hour
  movement is averaged.
- **Bloom false positives.** The lookup Bloom filter is a negative fast path only;
  false positives fall through to the exact structures (never a wrong match, just a
  little extra work). Tuned to <1%.
- **Aggregation state is in-process.** Count/distinct windows live in memory and
  reset on restart; they are not shared across processes.
- **PDF is optional.** `/posture report pdf` produces a PDF only if a rendering
  engine (e.g. WeasyPrint) is importable; otherwise it degrades to self-contained
  HTML (which prints to PDF from any browser via the `@page` rules).
- **Integrity sealing is best-effort.** If the Merkle integrity ledger DB isn't
  initialized, sealing self-disables cleanly; the rule version hash-chain and the
  report SHA-256 still stand on their own.
- **Sandbox note.** Some app-level test suites require third-party packages
  (telegram, httpx, …) not present in the offline sandbox; all v0.8 code and its
  tests are stdlib-only and telegram-free by design.
