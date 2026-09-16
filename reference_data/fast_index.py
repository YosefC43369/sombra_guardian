# -*- coding: utf-8 -*-
"""reference_data/fast_index.py — ค้นในไฟล์แบบ "ขั้นสูง + เร็ว" ในหน่วยความจำ (offline)

เทคโนโลยีค้นหาในไฟล์ที่เร็วขึ้นสำหรับ dataset อ้างอิง โดยไม่ต้องพึ่ง Elasticsearch:

  Trigram Inverted Index
  ----------------------
  แทนที่จะสแกนทุกระเบียนแล้วคิดคะแนน fuzzy ทีละตัว (O(N) ต่อคำค้น — ช้าเมื่อไฟล์ใหญ่)
  โมดูลนี้ทำดัชนีผกผัน (inverted index) จาก "trigram" (ชุดตัวอักษร 3 ตัวติดกัน) ของทุก
  ระเบียนไว้ล่วงหน้า เวลาค้นจะแตกคำค้นเป็น trigram แล้วดึงเฉพาะ "ผู้สมัคร" (candidate)
  ที่แชร์ trigram กัน — จัดอันดับผู้สมัครด้วยจำนวน trigram ที่ตรง แล้วค่อยให้คะแนนละเอียด
  (ตรงเป๊ะ/ขึ้นต้น/substring/fuzzy) เฉพาะผู้สมัคร top-K เท่านั้น → เร็วแบบ sub-linear และ
  ยังรองรับ fuzzy ได้แม้ไฟล์ใหญ่ (ต่างจากเดิมที่ต้องปิด fuzzy เมื่อเกินเพดาน)

  LRU query cache
  ---------------
  คำค้นซ้ำ ๆ (typeahead) คืนผลจากแคชทันที ไม่ต้องคิดใหม่

ขอบเขตปลอดภัย (เหมือนเดิม): ตัวสร้างระดับ dataset (for_dataset) ทำงานเฉพาะไฟล์ใน whitelist
ของ reference_data (airports, programming-languages) เท่านั้น — ไม่ใช่ engine ค้นทั่วไป
คลาส FastIndex เองเป็นโครงสร้างบริสุทธิ์ (รับ records ตรง ๆ) จึงเทส/ใช้ซ้ำได้อิสระ
ทั้งหมดเป็น pure-python (ไม่มี dependency ภายนอก) และไม่ throw ระดับคำค้น
"""

import re
import unicodedata
from collections import OrderedDict, defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import dataset_manager

_RE_WS = re.compile(r"\s+")
# โทเคน = อักษร/ตัวเลขละติน + อักษรไทย (฀-๿) เพื่อรองรับการพิมพ์/ค้นภาษาไทย
# (เดิม [a-z0-9]+ จะตัดอักษรไทยทิ้งทั้งหมด ทำให้ค้นชื่อ/เมืองภาษาไทยไม่เจอ)
_RE_TOKEN = re.compile(r"[a-z0-9฀-๿]+")

# ฟิลด์ที่ถือเป็น "ข้อความค้นได้" โดยดีฟอลต์ (ถ้าไม่ระบุ จะใช้ค่า string ทั้งหมดของ record)
_DEFAULT_TEXT_FIELDS = ("name", "city", "title", "label", "country", "state",
                        "code", "iata", "icao", "id", "key")


def _deaccent(text: str) -> str:
    # ตัดเฉพาะ "เครื่องหมายกำกับเสียงของอักษรละติน" (Combining Diacritical Marks
    # U+0300–U+036F) เพื่อให้ "Suárez"≈"Suarez" — แต่ "ไม่แตะ" วรรณยุกต์/สระไทย
    # (เช่น ่ ้ ็ ั ิ ี ึ ื ุ ู ซึ่งเป็น combining เหมือนกัน) มิฉะนั้นคำไทยจะเพี้ยน
    return "".join(c for c in unicodedata.normalize("NFKD", str(text))
                   if not (0x0300 <= ord(c) <= 0x036F))


def _norm(text: str) -> str:
    """normalize เทียบข้อความ: ตัด accent + lowercase + ยุบช่องว่าง"""
    return _RE_WS.sub(" ", _deaccent(str(text))).strip().lower()


def trigrams(text: str) -> List[str]:
    """แตกข้อความ (normalize แล้ว) เป็น trigram ต่อโทเคน — เติมช่องว่างหัวท้ายเพื่อจับขอบคำ

    เช่น "bkk" -> {" bk", "bkk", "kk "}; โทเคนสั้น (<3) เก็บทั้งโทเคนเป็นชิ้นเดียว
    """
    out: List[str] = []
    for tok in _RE_TOKEN.findall(_norm(text)):
        if len(tok) < 3:
            out.append(tok)
            continue
        padded = f" {tok} "
        for i in range(len(padded) - 2):
            out.append(padded[i:i + 3])
    return out


def _record_text(rec: dict, fields: Optional[Sequence[str]]) -> str:
    if fields:
        parts = [str(rec.get(f, "")) for f in fields if rec.get(f) not in (None, "")]
    else:
        parts = [v for v in rec.values() if isinstance(v, str) and v]
    return " ".join(parts)


def _precise_score(text_n: str, qn: str) -> int:
    """คะแนนละเอียดของผู้สมัคร (ยิ่งสูงยิ่งตรง) — ตรงเป๊ะ > ขึ้นต้น > substring > อื่น ๆ"""
    if not qn or not text_n:
        return 0
    if text_n == qn:
        return 100
    # โทเคนใดโทเคนหนึ่งตรง/ขึ้นต้นด้วยคำค้น
    toks = text_n.split()
    if qn in toks:
        return 90
    if text_n.startswith(qn) or any(t.startswith(qn) for t in toks):
        return 82
    if qn in text_n:
        return 60
    return 0


class FastIndex:
    """Trigram inverted index ในหน่วยความจำ + LRU cache สำหรับค้น record dict เร็ว ๆ"""

    def __init__(self, text_fields: Optional[Sequence[str]] = _DEFAULT_TEXT_FIELDS,
                 cache_size: int = 256):
        self._fields = tuple(text_fields) if text_fields else None
        self._docs: List[dict] = []
        self._doc_text: List[str] = []          # ข้อความ normalize ต่อ doc (ใช้ให้คะแนน)
        self._doc_tris: List[int] = []          # จำนวน trigram ต่อ doc (ใช้ normalize คะแนน)
        self._postings: Dict[str, List[int]] = defaultdict(list)
        self._cache: "OrderedDict[Tuple[str, int], List[dict]]" = OrderedDict()
        self._cache_size = max(0, int(cache_size))

    # ---------- build ----------
    def add(self, rec: dict) -> None:
        if not isinstance(rec, dict):
            return
        text = _record_text(rec, self._fields)
        if not text.strip():
            return
        doc_id = len(self._docs)
        self._docs.append(rec)
        text_n = _norm(text)
        self._doc_text.append(text_n)
        tris = set(trigrams(text))
        self._doc_tris.append(len(tris) or 1)
        for tg in tris:
            self._postings[tg].append(doc_id)

    def build(self, records: Iterable[dict]) -> "FastIndex":
        for rec in records:
            self.add(rec)
        return self

    def __len__(self) -> int:
        return len(self._docs)

    # ---------- search ----------
    def _candidates(self, q_tris: Sequence[str], max_candidates: int) -> List[Tuple[int, int]]:
        """คืน [(doc_id, จำนวน trigram ที่ตรง)] เรียงจากตรงมากไปน้อย (จำกัดจำนวน)"""
        overlap: Dict[int, int] = defaultdict(int)
        for tg in set(q_tris):
            posting = self._postings.get(tg)
            if not posting:
                continue
            for doc_id in posting:
                overlap[doc_id] += 1
        ranked = sorted(overlap.items(), key=lambda kv: -kv[1])
        return ranked[:max_candidates]

    def search(self, query: str, limit: int = 5,
               max_candidates: int = 200) -> List[dict]:
        """ค้น record ที่ตรงคำค้นที่สุด — เร็วแบบ sub-linear ผ่าน trigram pre-filter

        คืน list ของ record ต้นฉบับ (ไม่แก้ของเดิม), ว่างถ้าไม่มีคำค้น/ไม่พบ
        """
        qn = _norm(query)
        if not qn or not self._docs:
            return []
        key = (qn, int(limit))
        if self._cache_size and key in self._cache:
            self._cache.move_to_end(key)
            return list(self._cache[key])

        q_tris = trigrams(query)
        if not q_tris:
            return []
        candidates = self._candidates(q_tris, max_candidates)
        q_set = set(q_tris)

        scored: List[Tuple[float, int, int]] = []
        for doc_id, shared in candidates:
            text_n = self._doc_text[doc_id]
            precise = _precise_score(text_n, qn)
            # คะแนน trigram แบบ normalize (สัดส่วน trigram ของคำค้นที่ doc มี)
            tri_score = shared / max(1, len(q_set))
            score = precise + tri_score * 30      # ให้ความตรงเป๊ะ/ขึ้นต้นนำ, trigram เสริม
            if score <= 0:
                continue
            # เกณฑ์กันขยะ: ถ้าไม่ตรงเชิงข้อความเลย ต้องมี trigram ตรงพอสมควร
            if precise == 0 and tri_score < 0.34:
                continue
            scored.append((score, len(text_n), doc_id))

        scored.sort(key=lambda x: (-x[0], x[1]))
        results = [self._docs[doc_id] for _, _, doc_id in scored[: max(1, int(limit))]]

        if self._cache_size:
            self._cache[key] = list(results)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return results

    def clear_cache(self) -> None:
        self._cache.clear()


# ---------------- entry point ระดับ dataset (whitelist-gated) ----------------

# แคช index ต่อ (dataset, path) เพื่อไม่ต้องสร้างใหม่ทุกครั้ง — สร้างใหม่เมื่อไฟล์เปลี่ยน
_INDEX_CACHE: Dict[str, Tuple[str, FastIndex]] = {}


def for_dataset(name: str, text_fields: Optional[Sequence[str]] = _DEFAULT_TEXT_FIELDS,
                **opts) -> Optional[FastIndex]:
    """สร้าง/คืน FastIndex ของ dataset ใน whitelist (.json/.csv/.sql) — None ถ้านอก whitelist

    แคช index ไว้ต่อไฟล์และสร้างใหม่เมื่อ path/ไฟล์เปลี่ยน (ข้อมูลอนุพันธ์ rebuild ได้เสมอ)
    """
    if not dataset_manager.is_allowed(name):
        return None
    path = dataset_manager.get_dataset_path(name)
    if not path:
        return None
    cached = _INDEX_CACHE.get(name)
    if cached and cached[0] == path:
        return cached[1]
    try:
        idx = FastIndex(text_fields=text_fields).build(
            dataset_manager.get_records(name, **opts))
    except Exception:
        return None
    _INDEX_CACHE[name] = (path, idx)
    return idx


def search(name: str, query: str, limit: int = 5, **opts) -> List[dict]:
    """ค้นใน dataset ที่อนุญาตด้วย fast index — คืน [] ถ้านอก whitelist/หาไม่พบ (ไม่ throw)"""
    idx = for_dataset(name, **opts)
    if idx is None:
        return []
    return idx.search(query, limit=limit)


def invalidate(name: Optional[str] = None) -> None:
    """ล้าง index cache (ทั้งหมด หรือเฉพาะ dataset) — เรียกเมื่อรู้ว่าไฟล์อัปเดต"""
    if name is None:
        _INDEX_CACHE.clear()
    else:
        _INDEX_CACHE.pop(name, None)
