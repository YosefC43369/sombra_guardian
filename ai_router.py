# -*- coding: utf-8 -*-
"""
ai_router.py — ตัวจัดเส้นทาง LLM หลายผู้ให้บริการ พร้อม fallback อัตโนมัติ

ทำไมต้องมีโมดูลนี้
-----------------
gemini.py เดิมพูดกับผู้ให้บริการเดียว (OpenAI-compatible ตัวหนึ่ง) ถ้าเจ้านั้น
timeout / rate-limit / ล่ม ฟีเจอร์ AI ทั้งบอทก็เงียบ โมดูลนี้แทรกชั้น "เลือกโมเดล
+ สำรองโมเดล": ลงทะเบียนผู้ให้บริการหลายเจ้าจาก .env แล้ว

  1. จัดประเภทงานตามความหนัก (LIGHT / HEAVY) ด้วย heuristic ที่อธิบายได้
  2. งานเบา (จัดหมวด/สรุป URL/ถามสั้น) → โมเดลเร็ว โควตาสูง (Groq/Cerebras) ก่อน
  3. งานหนัก (เขียนโค้ด/วิเคราะห์บริบทยาว) → โมเดลใหญ่ (GPT/Gemini/OpenRouter) ก่อน
  4. ถ้าเจ้าที่เลือกล้มเหลว → ไล่ fallback ไปเจ้าถัดไปในสายทันที ด้วย timeout สั้น

ผู้ให้บริการทั้งหมดพูดโปรโตคอล OpenAI Chat Completions ได้ (รวม Gemini ผ่าน
endpoint OpenAI-compatible ของ Google) จึงใช้ ``openai.AsyncOpenAI`` ตัวเดียว
ต่างกันแค่ base_url + api_key + ชื่อโมเดล — ลดชนิด client เหลือหนึ่งเดียว

ค่าคอนฟิกอ่านจาก .env "ตอนเรียกใช้" เสมอ (ไม่ใช่ตอน import) เพราะ app.py เรียก
load_dotenv() หลังบล็อก import — รูปแบบเดียวกับ config.py

โมดูลนี้ไม่ผูกกับ Telegram และไม่โยน exception ออกไปหาผู้เรียก (จับทุกกรณีแล้วคืน
ผลลัพธ์แบบมีโครงสร้าง) เพื่อให้ event loop ของบอทไม่มีวันตายเพราะผู้ให้บริการเจ้าใด
"""

import os
import time
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("modbot.ai_router")

try:
    from openai import AsyncOpenAI
    HAVE_OPENAI = True
except Exception:  # pragma: no cover - environment without openai sdk
    AsyncOpenAI = None  # type: ignore
    HAVE_OPENAI = False


# ---------------- ประเภทงาน ----------------

LIGHT = "light"
HEAVY = "heavy"

# คีย์เวิร์ดที่บ่งชี้ "งานหนัก" (เขียน/วิเคราะห์โค้ด, เหตุผลหลายขั้น)
_HEAVY_HINTS = (
    "code", "โค้ด", "เขียนโปรแกรม", "function", "ฟังก์ชัน", "debug", "exploit",
    "reverse", "วิเคราะห์", "analyze", "analysis", "payload", "algorithm",
    "อัลกอริทึม", "refactor", "regex", "sql", "yara", "diff", "stack trace",
    "traceback", "จงเขียน", "ออกแบบ", "architecture", "โครงสร้าง",
)
# ความยาว prompt ที่เกินนี้ถือว่าเป็นงานหนัก (บริบทยาวต้องการโมเดลใหญ่)
_HEAVY_LEN = 900


def classify_task(prompt: str, *, force: Optional[str] = None) -> str:
    """คืน LIGHT หรือ HEAVY ตามเนื้อ prompt — อธิบายได้ ไม่ใช่กล่องดำ

    ``force`` ให้ผู้เรียกบังคับได้ (เช่นคำสั่งที่รู้อยู่แล้วว่าเป็นงานเบา)
    """
    if force in (LIGHT, HEAVY):
        return force
    text = (prompt or "").lower()
    if len(text) >= _HEAVY_LEN:
        return HEAVY
    if any(h in text for h in _HEAVY_HINTS):
        return HEAVY
    return LIGHT


# ---------------- ผู้ให้บริการ ----------------

@dataclass
class Provider:
    """หนึ่งผู้ให้บริการ LLM ที่พูด OpenAI Chat Completions ได้

    ``tier`` = 'fast' (เร็ว/โควตาสูง) หรือ 'big' (แม่นกว่า/ช้ากว่า)
    ``base_url`` = None หมายถึง endpoint ของ OpenAI ตรง ๆ
    """
    name: str
    api_key: str
    model: str
    tier: str                       # 'fast' | 'big'
    base_url: Optional[str] = None
    timeout: float = 45.0
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def make_client(self):
        if not HAVE_OPENAI:
            raise RuntimeError("openai sdk not installed")
        kwargs = {"api_key": self.api_key, "timeout": self.timeout}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.extra_headers:
            kwargs["default_headers"] = dict(self.extra_headers)
        return AsyncOpenAI(**kwargs)


# ตารางนิยามผู้ให้บริการ: (env_key, env_model, default_model, tier, base_url)
# อ่าน env ตอนเรียก build_providers() เสมอ
_PROVIDER_SPECS = [
    ("groq",      "GROQ_API_KEY",       "GROQ_MODEL",
     "llama-3.3-70b-versatile",     "fast", "https://api.groq.com/openai/v1"),
    ("cerebras",  "CEREBRAS_API_KEY",   "CEREBRAS_MODEL",
     "llama-3.3-70b",               "fast", "https://api.cerebras.ai/v1"),
    ("gpt",       "GPT_API_KEY",        "GPT_MODEL",
     "gpt-5.6-luna",                "big",  None),
    ("openai",    "OPENAI_API_KEY",     "OPENAI_MODEL",
     "gpt-5.6-luna",                "big",  None),
    ("gemini",    "GEMINI_API_KEY",     "GEMINI_ROUTER_MODEL",
     "gemini-2.5-flash",            "big",
     "https://generativelanguage.googleapis.com/v1beta/openai/"),
    ("openrouter", "OPENROUTER_API_KEY", "OPENROUTER_MODEL",
     "qwen/qwen-2.5-72b-instruct",  "big",  "https://openrouter.ai/api/v1"),
    ("mistral",   "MISTRAL_API_KEY",    "MISTRAL_MODEL",
     "mistral-large-latest",        "big",  "https://api.mistral.ai/v1"),
]


def _env(name: str) -> str:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else ""


def build_providers() -> List[Provider]:
    """ประกอบรายชื่อผู้ให้บริการจาก .env — เฉพาะเจ้าที่มี API key เท่านั้น
    (เจ้าที่ไม่ได้ตั้งคีย์จะถูกข้ามเงียบ ไม่ error)"""
    providers: List[Provider] = []
    seen_keys: set = set()
    for name, key_env, model_env, default_model, tier, base in _PROVIDER_SPECS:
        api_key = _env(key_env)
        if not api_key:
            continue
        # gpt กับ openai มักใช้คีย์เดียวกัน — อย่าลงทะเบียนซ้ำสองเจ้าเหมือนกัน
        dedup = (base or "openai", api_key)
        if dedup in seen_keys:
            continue
        seen_keys.add(dedup)
        model = _env(model_env) or default_model
        extra = {}
        if name == "openrouter":
            extra = {"HTTP-Referer": "https://sombra.guardian",
                     "X-Title": "SombraGuardian"}
        providers.append(Provider(name=name, api_key=api_key, model=model,
                                   tier=tier, base_url=base, extra_headers=extra))
    return providers


def router_configured() -> bool:
    """True เมื่อมีผู้ให้บริการอย่างน้อยหนึ่งเจ้าถูกตั้งคีย์ไว้"""
    return HAVE_OPENAI and bool(build_providers())


def _ordered_for_task(providers: List[Provider], task: str) -> List[Provider]:
    """เรียงผู้ให้บริการตามประเภทงาน: งานเบาเอา fast ขึ้นก่อน งานหนักเอา big ขึ้นก่อน
    ที่เหลือต่อท้ายเป็น fallback — ทุกเจ้าอยู่ในสายเสมอ จะได้ไม่มีทางตัน"""
    if task == LIGHT:
        primary = [p for p in providers if p.tier == "fast"]
        rest = [p for p in providers if p.tier != "fast"]
    else:
        primary = [p for p in providers if p.tier == "big"]
        rest = [p for p in providers if p.tier != "big"]
    return primary + rest


@dataclass
class RouterResult:
    ok: bool
    text: str = ""
    provider: str = ""
    model: str = ""
    task: str = ""
    attempts: int = 0
    tried: List[str] = field(default_factory=list)
    reason: str = ""
    elapsed_ms: int = 0


def _switch_timeout(task: str, provider: Provider) -> float:
    """timeout ต่อเจ้าหนึ่ง ๆ — งานเบาให้สั้น (สลับเจ้าไว) งานหนักให้ยาวขึ้น
    override ได้ด้วย AI_ROUTER_LIGHT_TIMEOUT / AI_ROUTER_HEAVY_TIMEOUT"""
    if task == LIGHT:
        base = float(_env("AI_ROUTER_LIGHT_TIMEOUT") or 12.0)
    else:
        base = float(_env("AI_ROUTER_HEAVY_TIMEOUT") or 45.0)
    return min(base, provider.timeout)


async def _call_one(provider: Provider, messages: List[dict], task: str,
                    *, temperature: Optional[float]) -> Tuple[bool, str, str]:
    """เรียกผู้ให้บริการหนึ่งเจ้า คืน (ok, text_or_reason, kind)
    kind ∈ ok | retryable | fatal — retryable ให้ไป fallback ต่อ, fatal เช่นกัน
    แต่แยกไว้เพื่อ log/สถิติ"""
    client = provider.make_client()
    kwargs = {"model": provider.model, "messages": messages}
    if temperature is not None:
        kwargs["temperature"] = temperature
    try:
        resp = await asyncio.wait_for(
            client.chat.completions.create(**kwargs),
            timeout=_switch_timeout(task, provider),
        )
    except asyncio.TimeoutError:
        return False, "timeout", "retryable"
    except Exception as exc:  # rate-limit / auth / connection / ฯลฯ
        name = type(exc).__name__
        low = f"{name}: {exc}".lower()
        kind = "retryable" if any(
            s in low for s in ("rate", "timeout", "overload", "503", "502",
                               "500", "429", "connection", "unavailable")
        ) else "fatal"
        return False, f"{name}", kind
    finally:
        try:
            await client.close()
        except Exception:
            pass

    try:
        text = (resp.choices[0].message.content or "").strip()
    except (AttributeError, IndexError):
        return False, "empty response", "retryable"
    if not text:
        return False, "empty response", "retryable"
    return True, text, "ok"


async def route(
    prompt: str,
    *,
    system: Optional[str] = None,
    task: Optional[str] = None,
    temperature: Optional[float] = None,
    providers: Optional[List[Provider]] = None,
) -> RouterResult:
    """ส่ง ``prompt`` ผ่านสาย fallback ตามประเภทงาน คืน RouterResult

    - ``task`` = LIGHT/HEAVY (ถ้า None จะจัดประเภทให้อัตโนมัติ)
    - ``system`` = system prompt (ถ้ามี)
    ไม่โยน exception — ทุกความล้มเหลวสรุปใน RouterResult.ok=False
    """
    start = time.monotonic()
    task = task or classify_task(prompt)
    provs = providers if providers is not None else build_providers()
    if not provs:
        return RouterResult(ok=False, task=task, reason="no provider configured")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    ordered = _ordered_for_task(provs, task)
    tried: List[str] = []
    last_reason = ""
    for provider in ordered:
        tried.append(provider.name)
        ok, payload, kind = await _call_one(provider, messages, task,
                                            temperature=temperature)
        if ok:
            return RouterResult(
                ok=True, text=payload, provider=provider.name,
                model=provider.model, task=task, attempts=len(tried),
                tried=tried, elapsed_ms=int((time.monotonic() - start) * 1000),
            )
        last_reason = f"{provider.name}: {payload}"
        logger.info("AI ROUTER | %s ล้มเหลว (%s/%s) — สลับเจ้าถัดไป",
                    provider.name, payload, kind)

    return RouterResult(
        ok=False, task=task, attempts=len(tried), tried=tried,
        reason=last_reason or "all providers failed",
        elapsed_ms=int((time.monotonic() - start) * 1000),
    )


def describe_providers() -> str:
    """ข้อความสรุปผู้ให้บริการที่พร้อมใช้ (สำหรับ /status หรือ log) — ไม่โชว์คีย์"""
    provs = build_providers()
    if not HAVE_OPENAI:
        return "AI Router: openai sdk ยังไม่ได้ติดตั้ง"
    if not provs:
        return "AI Router: ยังไม่มีผู้ให้บริการ (ตั้งคีย์เจ้าใดเจ้าหนึ่งใน .env)"
    fast = [p.name for p in provs if p.tier == "fast"]
    big = [p.name for p in provs if p.tier == "big"]
    parts = []
    if big:
        parts.append("หนัก→ " + ", ".join(f"{p.name}({p.model})"
                                            for p in provs if p.tier == "big"))
    if fast:
        parts.append("เบา→ " + ", ".join(f"{p.name}({p.model})"
                                          for p in provs if p.tier == "fast"))
    return "AI Router พร้อมใช้: " + " | ".join(parts)
