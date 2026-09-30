# AI pipeline

The AI turns **structured, verified facts** into a natural Thai summary. It is an
enhancement layer: when it is unavailable or its output can't be validated, the
subsystem still publishes a factual alert from a deterministic template
(rule §16). Credentials and provider selection stay owned by the host project.

## Flow

```
CVERecord ──▶ prompt_builder ──▶ adapter (ai_router → gemini) ──▶ validator
   │             (facts + untrusted        │ provider-agnostic      │
   │              description, delimited)   ▼                         ▼
   │                                    AIResult ──────────▶ ok? build AISummary
   └──────────────────── cache (cve_id + input_hash) ◀──────┘   │ fail?
                                                                 ▼
                                                      deterministic fallback
                                                      (analyzer recommendations)
```

## The adapter (`ai/adapter.py`)

Exposes one coroutine, `generate(prompt, system, task)`, over the two AI entry
points the project already ships — `ai_router.route` (multi-provider, preferred)
and `gemini.ask_gemini` — with a cross-backend fallback. The CVE subsystem never
knows or cares whether the backend is Gemini, OpenAI, Groq, etc.

## The prompt (`ai/prompt_builder.py`)

The model receives two clearly separated parts:

* **`STRUCTURED_FACTS`** — a JSON object of verified, normalized facts (CVSS with
  per-source provenance, CWE labels, vendors, products, KEV status, exploit
  status, exposure). The model must not contradict these.
* **`<CVE_DESCRIPTION>…</CVE_DESCRIPTION>`** — the one untrusted free-text input,
  explicitly delimited. The system instruction tells the model to treat anything
  inside it as data, never as instructions (**prompt-injection defence**,
  rule §54).

The system instruction (a vulnerability-analyst persona, deliberately separate
from the bot's chat persona) forbids inventing CVSS scores, products, vendors,
versions, patch status, or exploit availability, and requires the fixed phrases
`ไม่พบข้อมูล` / `ยังไม่มีข้อมูลยืนยัน…` when a fact is absent.

## Validation (`ai/validator.py`)

Before any summary is sent it is checked against the facts (rule §15):

* **CVE-id confusion** — a wrong CVE id in the text is repaired (replaced) or
  rejected.
* **Fabricated CVSS** — a CVSS number not present in the facts fails validation.
* **Over-claiming** — a "exploited in the wild"/KEV claim when the facts say
  KEV=false fails validation.
* **Length / format** — over-long fields are truncated; empty/malformed JSON
  fails.

On a repairable issue the validator repairs and continues; on an unrepairable
one it fails, and the summarizer retries once with the specific problem fed back,
then falls back.

## Fallback (`ai/analyzer.py` + `ai/summarizer.py`)

The deterministic fallback builds the Thai body from the facts alone: the
original title/description, a CVSS-derived impact sentence, and standard
blue-team recommendations tailored to the record (check inventory, check
version, watch for a vendor patch, segment the network, and — for KEV/exploit —
raise monitoring). It is marked `fallback_used` and **not cached**, so a
recovered AI is used next time.

## Caching (`ai/cache.py`)

Two tiers keyed on `(cve_id, input_hash)`, where `input_hash` is derived from the
facts that drive the summary. An unchanged CVE reuses its summary; only
validated (non-fallback) summaries are cached.
