"""เทสการค้นหาที่รองรับตัวอักษรภาษาไทย (Thai-aware search)

ครอบคลุมฟังก์ชันใหม่ใน osint.py:
  - normalize_thai_query : NFC + ตัดอักขระล่องหน + ยุบวรรณยุกต์ซ้ำ + ยุบช่องว่าง
  - contains_thai        : ตรวจว่ามีอักษรไทย
  - thai_tokens / thai_keywords : ตัดคำค้นไทย โดยตัด stopword/ป้ายกำกับ/คำ generic
และการต่อยอดใน extract_selectors / plan_queries ให้ "พิมพ์ไทยแล้วค้นเจอ"
โดยไม่ทำของเดิม (อังกฤษ/ชื่อบุคคล) พัง

นำเข้าเฉพาะ osint (stdlib ล้วน) จึงรันได้โดยไม่ต้องมี httpx/bs4/openai
"""
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import osint

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))


# ---------- contains_thai ----------
check("contains_thai: ไทย", osint.contains_thai("บริษัท") is True)
check("contains_thai: อังกฤษล้วน", osint.contains_thai("acme corp") is False)
check("contains_thai: ว่าง/None", osint.contains_thai("") is False and osint.contains_thai(None) is False)


# ---------- normalize_thai_query ----------
# ตัดอักขระล่องหน (zero-width space U+200B) ที่คีย์บอร์ด/การคัดลอกแทรกมา
check("normalize: ตัด zero-width", osint.normalize_thai_query("บริษัท​เอบีซี") == "บริษัทเอบีซี",
      repr(osint.normalize_thai_query("บริษัท​เอบีซี")))
# ยุบวรรณยุกต์ที่พิมพ์ซ้ำติดกัน (กดค้างบนมือถือ) — ก + ไม้เอกสองตัว -> ก + ไม้เอกตัวเดียว
check("normalize: ยุบวรรณยุกต์ซ้ำ", osint.normalize_thai_query("ก่่อ") == "ก่อ",
      repr(osint.normalize_thai_query("ก่่อ")))
# ยุบช่องว่างซ้ำ + ตัดหัวท้าย
check("normalize: ยุบช่องว่าง", osint.normalize_thai_query("  สมชาย   ใจดี  ") == "สมชาย ใจดี")
# NFC คงสระอำไว้ (ไม่แตกแบบ NFKC) — ความยาวคงเดิม
check("normalize: คงสระอำ (จำกัด)", osint.normalize_thai_query("จำกัด") == "จำกัด")
# ปลอดภัยกับอังกฤษ (เปลี่ยนแค่ช่องว่าง)
check("normalize: อังกฤษไม่เพี้ยน", osint.normalize_thai_query("  John   Doe ") == "John Doe")
check("normalize: None -> ''", osint.normalize_thai_query(None) == "")


# ---------- thai_tokens / thai_keywords ----------
# ตัด stopword ออก เหลือคำเนื้อหา (ใช้ stopword ที่คงที่ ไม่ยึดคำที่ปรับได้อย่าง "รั่วไหล")
check("keywords: ตัด stopword เหลือคำเนื้อหา",
      osint.thai_keywords("ช่วยหาข้อมูลเกี่ยวกับ เอบีซี") == ["เอบีซี"],
      osint.thai_keywords("ช่วยหาข้อมูลเกี่ยวกับ เอบีซี"))
# คำ generic (บริษัท/จำกัด/มหาชน) ถูกกรองออก
check("keywords: กรองคำ generic",
      osint.thai_keywords("บริษัท จำกัด มหาชน") == [],
      osint.thai_keywords("บริษัท จำกัด มหาชน"))
# ป้ายกำกับ (เบอร์) ถูกกรองออก ไม่ปนเป็นคำค้น
check("keywords: กรองป้ายกำกับ 'เบอร์'",
      "เบอร์" not in osint.thai_keywords("สมชาย เบอร์ 0812345678"),
      osint.thai_keywords("สมชาย เบอร์ 0812345678"))
# อักษรไทยเดี่ยวไม่นับเป็นคำค้น
check("keywords: อักษรเดี่ยวถูกทิ้ง", "ก" not in osint.thai_tokens("ก ขข คคค"))
# อังกฤษล้วน -> ไม่มี token ไทย
check("keywords: อังกฤษล้วนได้ []", osint.thai_keywords("leaked data acme") == [])
# จำกัดจำนวน
check("keywords: เคารพ limit",
      len(osint.thai_keywords("กขค งจฉ ชซฌ ญฎฏ ฐฑฒ ณดต", limit=2)) == 2,
      osint.thai_keywords("กขค งจฉ ชซฌ ญฎฏ ฐฑฒ ณดต", limit=2))


# ---------- extract_selectors: คำค้นไทยไม่หายเมื่อมี selector อื่น ----------
# ของเดิมเก็บเฉพาะ token ละติน คำไทยจึงหายหมดเมื่อมีโดเมน — ตอนนี้ต้องอยู่รอด
sel = osint.extract_selectors("ข้อมูลรั่วไหล บริษัทเอบีซี acme.co.th")
check("selectors: โดเมนยังจับได้", "acme.co.th" in [d.lower() for d in sel.domains], sel.domains)
check("selectors: คำค้นไทยไม่หาย", any("เอบีซี" in k for k in sel.keywords), sel.keywords)

# zero-width ในคำค้นไม่ทำให้สกัด selector พลาด
sel2 = osint.extract_selectors("อีเมล john.doe@acme.co.th​ รั่ว")
check("selectors: zero-width ไม่กระทบอีเมล", sel2.emails == ["john.doe@acme.co.th"], sel2.emails)


# ---------- plan_queries: คำถามไทยล้วนได้ query ที่ใช้งานได้ ----------
plan = osint.plan_queries("ช่วยตรวจสอบข้อมูลที่รั่วไหลของ ธนวัฒน์ ศรีสุข หน่อย")
check("plan: คำถามไทยล้วนไม่ว่าง", plan != [])
check("plan: มีวลีชื่อแบบตรงตัว", any(q.startswith('"') for q in plan), plan)

# ไม่มี selector และไม่ใช่ชื่อ -> ต้องได้คำค้นไทยที่คัดแล้ว (ไม่ใช่ทั้งประโยค)
plan2 = osint.plan_queries("ช่วยหาข่าวข้อมูลรั่วไหลเว็บมืด")
check("plan: fallback ตัดเหลือคำเนื้อหา", plan2 != [] and all("ช่วย" not in q for q in plan2), plan2)

# regression: อังกฤษ + อีเมล ยังได้แผนเดิม (email, domain pivot, local-part)
plan_en = osint.plan_queries("leak of john.doe@acme.co.th")
check("plan: อังกฤษ/อีเมลยังทำงานเดิม",
      "john.doe@acme.co.th" in plan_en and "acme.co.th" in plan_en, plan_en)


print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
