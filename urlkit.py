# -*- coding: utf-8 -*-
"""urlkit.py — ชุดเครื่องมือจัดการ URL แบบพึ่งพาเฉพาะไลบรารีมาตรฐาน

โมดูลเล็ก ๆ ที่ reputation.py (และโมดูลอื่น ๆ ที่ต้องแตะลิงก์) เรียกใช้ เพื่อ:

  * ``extract(url)``        แยกส่วนประกอบของ URL ออกมาเป็น ``ExtractedURL``
  * ``extract_urls(text)``  กวาดหา URL ทั้งหมดในข้อความ (เช่นข้อความแชต)
  * ``etld1(host_or_url)``  คืนค่า "โดเมนจดทะเบียน" (effective TLD+1 / eTLD+1)
                            เช่น ``a.b.example.co.uk`` -> ``example.co.uk``

ออกแบบตามแนวทางเดียวกับส่วนอื่นของโปรเจกต์:
  - ไม่พึ่ง dependency ภายนอก (ไม่ต้องมี tldextract / publicsuffix2) เทสต์ได้ง่าย
  - ฟังก์ชันเป็น pure logic คืนค่าเดิมเสมอสำหรับอินพุตเดิม
  - ทนอินพุตเพี้ยน ๆ: ว่าง, None, มีช่องว่าง, ไม่มี scheme, เป็น IP, เป็น IDN

การหา eTLD+1 ใช้วิธี "Public Suffix List แบบย่อ" ที่ฝังไว้ในไฟล์นี้ ครอบคลุมสิ่งที่
พบจริงเกือบทั้งหมด (ccTLD สองระดับอย่าง co.uk / com.au / co.th รวมถึง wildcard และ
ข้อยกเว้นหลัก ๆ) และมี heuristic สำรองสำหรับ ccTLD สองตัวอักษรที่ตามด้วยป้ายกำกับ
ระดับองค์กรที่พบบ่อย (co/com/net/org/gov/edu/ac/or/ne/go ...)
"""

from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple
from urllib.parse import urlsplit, unquote

__all__ = ["ExtractedURL", "extract", "extract_urls", "etld1", "registered_domain"]

# ---------------------------------------------------------------------------
# Public Suffix List (ชุดย่อแบบฝังในไฟล์)
# ---------------------------------------------------------------------------
# กฎ:
#   - รายการธรรมดา เช่น "co.uk"  => เป็น public suffix ตรงตัว
#   - รายการ wildcard เช่น "*.ck" => ป้ายกำกับใด ๆ ที่นำหน้า ".ck" เป็น suffix
#   - รายการข้อยกเว้น เช่น "!www.ck" (นำหน้าด้วย "!") => ตัดออกจาก wildcard
# หมายเหตุ: นี่คือชุดย่อ ไม่ใช่ PSL เต็ม แต่พอสำหรับงานตรวจลิงก์ทั่วไปของบอต

_PUBLIC_SUFFIXES_RAW = """
# generic multi-level ที่พบบ่อย
co.com eu.com us.com uk.com gb.com
# United Kingdom
co.uk org.uk me.uk ltd.uk plc.uk net.uk sch.uk ac.uk gov.uk nhs.uk police.uk mod.uk
# Australia
com.au net.au org.au edu.au gov.au asn.au id.au
# New Zealand
co.nz net.nz org.nz govt.nz ac.nz geek.nz gen.nz kiwi.nz school.nz
# Japan
co.jp or.jp ne.jp ac.jp go.jp gr.jp ad.jp ed.jp lg.jp
# South Korea
co.kr or.kr ne.kr re.kr pe.kr go.kr mil.kr ac.kr hs.kr ms.kr es.kr sc.kr
# China
com.cn net.cn org.cn gov.cn edu.cn ac.cn mil.cn
# Hong Kong / Taiwan
com.hk net.hk org.hk edu.hk gov.hk idv.hk
com.tw net.tw org.tw edu.tw gov.tw idv.tw game.tw ebiz.tw club.tw
# Thailand
co.th or.th ac.th go.th in.th mi.th net.th
# India
co.in net.in org.in gen.in firm.in ind.in ac.in edu.in gov.in mil.in res.in
# Brazil
com.br net.br org.br gov.br edu.br mil.br art.br blog.br
# South Africa
co.za org.za net.za gov.za ac.za web.za
# Russia / ex-USSR
com.ru net.ru org.ru pp.ru msk.ru spb.ru
com.ua net.ua org.ua in.ua kiev.ua
# Mexico / Argentina
com.mx org.mx net.mx edu.mx gob.mx
com.ar net.ar org.ar gov.ar edu.ar int.ar mil.ar
# Singapore / Malaysia / Indonesia / Philippines
com.sg net.sg org.sg edu.sg gov.sg per.sg
com.my net.my org.my edu.my gov.my mil.my name.my
co.id or.id web.id net.id ac.id go.id sch.id my.id biz.id
com.ph net.ph org.ph gov.ph edu.ph
# Turkey / Israel / Saudi / UAE / Egypt
com.tr net.tr org.tr gov.tr edu.tr bel.tr web.tr
co.il org.il net.il ac.il gov.il muni.il idf.il
com.sa net.sa org.sa gov.sa edu.sa med.sa pub.sa sch.sa
co.ae net.ae org.ae gov.ae ac.ae sch.ae
com.eg net.eg org.eg gov.eg edu.eg
# Europe misc.
co.at or.at gv.at ac.at
com.pl net.pl org.pl gov.pl edu.pl waw.pl
com.gr net.gr org.gr gov.gr edu.gr
com.es nom.es org.es gob.es edu.es
# wildcard + exceptions (ตัวอย่างมาตรฐานจาก PSL)
*.ck !www.ck
*.jm
*.fj
*.pg
"""


def _load_suffixes(raw: str) -> Tuple[Set[str], Set[str], Set[str]]:
    exact: Set[str] = set()
    wildcard: Set[str] = set()   # เก็บส่วนหลัง "*."  เช่น "ck"
    exceptions: Set[str] = set()
    for line in raw.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        for item in token.split():
            if item.startswith("!"):
                exceptions.add(item[1:].lower().strip("."))
            elif item.startswith("*."):
                wildcard.add(item[2:].lower().strip("."))
            else:
                exact.add(item.lower().strip("."))
    return exact, wildcard, exceptions


_EXACT_SUFFIXES, _WILDCARD_SUFFIXES, _SUFFIX_EXCEPTIONS = _load_suffixes(_PUBLIC_SUFFIXES_RAW)

# ป้ายกำกับระดับองค์กรที่พบบ่อย ใช้กับ heuristic ccTLD สองตัวอักษร
_SECOND_LEVEL_HINTS = {
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go",
    "gob", "gouv", "mil", "int", "nom", "info", "biz", "name", "web",
    "sch", "res", "ind", "gen", "firm", "idv", "govt",
}

# regex หา URL ในข้อความอิสระ (จับทั้งที่มี scheme และขึ้นต้นด้วย www.)
_URL_RE = re.compile(
    r"""(?xi)
    \b
    (
        (?:https?|ftp|ftps|sftp)://[^\s<>"'`\]\)}]+     # มี scheme
      | www\.[^\s<>"'`\]\)}]+                            # ขึ้นต้น www.
    )
    """,
)

# ตัวอักษรท้าย URL ที่มักเป็นเครื่องหมายวรรคตอน ไม่ใช่ส่วนของลิงก์
_TRAILING_PUNCT = ".,;:!?\"')]}>»”’"


# ---------------------------------------------------------------------------
# โครงสร้างผลลัพธ์
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExtractedURL:
    """ผลการแยก URL หนึ่งรายการ (immutable)

    ตัวอย่าง: ``https://a.b.Example.CO.UK:8443/p?x=1#f``
      raw                = "https://a.b.Example.CO.UK:8443/p?x=1#f"
      scheme             = "https"
      host               = "a.b.example.co.uk"
      port               = 8443
      subdomain          = "a.b"
      domain             = "example"          (label ก่อน suffix)
      suffix             = "co.uk"            (public suffix)
      registered_domain  = "example.co.uk"    (eTLD+1)
      path/query/fragment = "/p" / "x=1" / "f"
      is_ip              = False
    """
    raw: str
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    subdomain: str = ""
    domain: str = ""
    suffix: str = ""
    registered_domain: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_ip: bool = False

    # ---- helper ที่ใช้บ่อยในฝั่งเรียก ----
    @property
    def etld1(self) -> str:
        """alias ของ registered_domain (eTLD+1)"""
        return self.registered_domain

    @property
    def is_valid(self) -> bool:
        """มี host ที่ใช้งานได้จริงไหม"""
        return bool(self.host)

    def __str__(self) -> str:
        return self.registered_domain or self.host or self.raw


# ---------------------------------------------------------------------------
# แกนการแยกโดเมน (eTLD+1)
# ---------------------------------------------------------------------------

def _normalize_host(host: str) -> str:
    """ทำให้ host เป็นรูปแบบมาตรฐาน: ตัดช่องว่าง, ลดเป็นตัวเล็ก, ตัดจุดท้าย,
    แปลง IDN (unicode) เป็น punycode ถ้าทำได้"""
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    # ตัด userinfo ถ้าหลุดมา
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    # IPv6 literal ที่ครอบด้วย [...] -> ถอดวงเล็บออกให้เป็น IP สะอาด
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    # IDN -> punycode (ไม่ให้ล้มถ้าแปลงไม่ได้)
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            # fallback ราย label
            try:
                host = ".".join(
                    lbl.encode("idna").decode("ascii") if lbl else lbl
                    for lbl in host.split(".")
                )
            except Exception:
                pass
    return host


def _is_ip_literal(host: str) -> bool:
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _public_suffix_of(labels: List[str]) -> List[str]:
    """คืน list ของ label ที่ประกอบเป็น public suffix (ยาวที่สุดที่แมตช์)

    ใช้ชุดย่อที่ฝังไว้ + heuristic ccTLD สองตัวอักษร
    ดีฟอลต์ขั้นต่ำ = label สุดท้าย (TLD ตัวเดียว)
    """
    n = len(labels)
    if n == 0:
        return []
    if n == 1:
        return labels[:]  # เช่น "localhost"

    # 1) exact match: ลองจากยาวสุดลงมา (ระดับ 3 -> 2)
    for size in (3, 2):
        if n >= size:
            cand = ".".join(labels[-size:])
            if cand in _EXACT_SUFFIXES:
                return labels[-size:]

    # 2) wildcard match: *.X  => ป้ายกำกับใด ๆ + X เป็น suffix (เว้นข้อยกเว้น)
    last = labels[-1]
    if last in _WILDCARD_SUFFIXES and n >= 2:
        two = ".".join(labels[-2:])
        if two not in _SUFFIX_EXCEPTIONS:
            return labels[-2:]
        # ตรงข้อยกเว้น -> suffix เหลือแค่ TLD
        return labels[-1:]

    # 3) heuristic: ccTLD สองตัวอักษร + ป้ายกำกับระดับองค์กรที่พบบ่อย
    #    เช่น "something.go.cc" ที่ไม่อยู่ใน exact list
    if n >= 2 and len(last) == 2 and last.isalpha():
        second = labels[-2]
        if second in _SECOND_LEVEL_HINTS:
            return labels[-2:]

    # 4) ดีฟอลต์: TLD ตัวเดียว
    return labels[-1:]


def _split_registered(host: str) -> Tuple[str, str, str, str]:
    """คืน (subdomain, domain, suffix, registered_domain)

    - host ควรถูก normalize มาก่อน
    - ถ้าเป็น IP หรือ host ชั้นเดียว จะคืน registered_domain = host ตามเหมาะสม
    """
    if not host:
        return "", "", "", ""

    if _is_ip_literal(host):
        return "", host, "", host

    labels = [lbl for lbl in host.split(".") if lbl != ""]
    if not labels:
        return "", "", "", ""
    if len(labels) == 1:
        # เช่น "localhost" — ไม่มี suffix จริง
        return "", labels[0], "", labels[0]

    suffix_labels = _public_suffix_of(labels)
    suffix = ".".join(suffix_labels)
    s = len(suffix_labels)

    if len(labels) <= s:
        # host เป็น public suffix ล้วน ๆ (เช่น "co.uk") — ไม่มีโดเมนจดทะเบียน
        return "", "", suffix, suffix

    domain = labels[-(s + 1)]
    registered = ".".join(labels[-(s + 1):])
    subdomain = ".".join(labels[: -(s + 1)])
    return subdomain, domain, suffix, registered


# ---------------------------------------------------------------------------
# API สาธารณะ
# ---------------------------------------------------------------------------

def extract(url: str) -> ExtractedURL:
    """แยก URL (หรือ host เปล่า ๆ) ออกเป็น ``ExtractedURL``

    ทนอินพุตที่ไม่มี scheme: ถ้าไม่มี "://" จะเติม "http://" ชั่วคราวเพื่อ parse
    คืน ExtractedURL ที่ host ว่างถ้าแยกไม่ได้ (ไม่ throw)
    """
    if not url:
        return ExtractedURL(raw=url or "")

    raw = url
    candidate = url.strip()

    # เติม scheme ชั่วคราวถ้าจำเป็น เพื่อให้ urlsplit แยก netloc ถูก
    has_scheme = bool(re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", candidate))
    parse_target = candidate if has_scheme else "http://" + candidate

    try:
        parts = urlsplit(parse_target)
    except ValueError:
        return ExtractedURL(raw=raw)

    scheme = parts.scheme.lower() if has_scheme else ""
    hostname = parts.hostname or ""
    host = _normalize_host(hostname)

    port: Optional[int] = None
    try:
        port = parts.port
    except ValueError:
        port = None

    subdomain, domain, suffix, registered = _split_registered(host)

    return ExtractedURL(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=registered,
        path=parts.path or "",
        query=parts.query or "",
        fragment=parts.fragment or "",
        is_ip=_is_ip_literal(host) if host else False,
    )


def etld1(host_or_url: str) -> str:
    """คืน effective TLD+1 (โดเมนจดทะเบียน) จาก host หรือ URL เต็ม

    ตัวอย่าง:
      etld1("https://a.b.example.co.uk/x") -> "example.co.uk"
      etld1("sub.example.com")             -> "example.com"
      etld1("8.8.8.8")                      -> "8.8.8.8"
      etld1("")                             -> ""
    """
    if not host_or_url:
        return ""
    s = host_or_url.strip()
    # ถ้าดูเหมือน URL (มี scheme หรือมี path/slash) ให้ parse ผ่าน extract
    if "://" in s or "/" in s or "?" in s or "@" in s:
        return extract(s).registered_domain
    # ไม่งั้นถือเป็น host เปล่า ๆ
    host = _normalize_host(s)
    return _split_registered(host)[3]


# alias ชื่อที่คนมักเรียก
registered_domain = etld1


def extract_urls(text: str, *, dedupe: bool = False) -> List[ExtractedURL]:
    """กวาดหา URL ทั้งหมดในข้อความอิสระ แล้วคืน list ของ ExtractedURL

    - จับทั้งลิงก์ที่มี scheme และที่ขึ้นต้นด้วย ``www.``
    - ตัดเครื่องหมายวรรคตอนท้ายลิงก์ (เช่น จุด/วงเล็บ) ออก
    - ``dedupe=True`` จะยุบลิงก์ที่ raw ซ้ำกันให้เหลือรายการเดียว (คงลำดับเดิม)
    """
    if not text:
        return []

    out: List[ExtractedURL] = []
    seen: Set[str] = set()
    for m in _URL_RE.finditer(text):
        token = m.group(1).rstrip(_TRAILING_PUNCT)
        # ถ้าวงเล็บเปิด/ปิดไม่สมดุล ให้ตัดวงเล็บปิดเกินท้ายทิ้ง
        if token.endswith(")") and token.count("(") < token.count(")"):
            token = token[:-1]
        if not token:
            continue
        if dedupe:
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
        out.append(extract(token))
    return out


if __name__ == "__main__":  # self-check เล็ก ๆ รันได้ตรง ๆ
    samples = [
        "https://a.b.Example.CO.UK:8443/path?q=1#frag",
        "sub.domain.example.com",
        "www.example.co.th/page",
        "http://8.8.8.8/health",
        "http://[2001:db8::1]:8080/",
        "แวะดู https://github.com/foo/bar, และ www.google.com ด้วยนะ",
        "เว็บไทย https://news.bbc.co.uk ครับ",
    ]
    for s in samples:
        if " " in s and ("http" in s or "www." in s):
            for e in extract_urls(s):
                print(f"[extract_urls] {e.host:28s} etld1={e.etld1}")
        else:
            e = extract(s)
            print(f"[extract]      {e.host:28s} etld1={e.etld1} ip={e.is_ip}")
