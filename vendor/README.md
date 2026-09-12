# vendor/ — สำเนาซอร์สจากแพ็กเกจ maigret

ไฟล์ในโฟลเดอร์นี้ (`sites.py`, `checkings.py`, `maigret.py`) เป็นสำเนาซอร์สของ
แพ็กเกจ [maigret](https://pypi.org/project/maigret/) ที่ถูกดึงออกมาวางไว้ที่ราก
โปรเจกต์ **เก็บไว้ครบทุกบรรทัด ไม่ได้ลบหรือแก้อะไร** แต่ย้ายมาที่นี่เพราะวางไว้
ที่รากแล้วใช้งานไม่ได้และยังก่อปัญหาให้ไฟล์อื่น

## ทำไมไฟล์เหล่านี้ import ไม่ได้

```
import sites     -> ImportError: attempted relative import with no known parent package
import checkings -> ModuleNotFoundError: No module named 'aiodns'
import maigret   -> ModuleNotFoundError: No module named 'maigret.utils'; 'maigret' is not a package
```

สามสาเหตุพร้อมกัน:

1. **ใช้ relative import** — `sites.py` มี `from .utils import ...`,
   `checkings.py` มี `from . import errors` ซึ่งทำงานได้เฉพาะเมื่ออยู่ในแพ็กเกจ
2. **ขาดโมดูลพี่น้อง** ที่ไม่ได้ถูกคัดลอกมาด้วย — `utils`, `errors`,
   `activation`, `result`, `report`, `notify`, `submit`, `settings`, `__version__`
3. **ขาดแพ็กเกจภายนอก 7 ตัว** ที่ไม่มีใน `requirements.txt` — `aiodns`,
   `aiohttp`, `aiohttp_socks`, `alive_progress`, `curl_cffi`, `socid_extractor`,
   `maigret`

## ทำไมต้องย้ายออกจากราก

`maigret.py` ที่รากโปรเจกต์ **บังแพ็กเกจ `maigret` ตัวจริง** เพราะ Python ค้น
โฟลเดอร์ของสคริปต์ก่อน `site-packages` ต่อให้ `pip install maigret` แล้ว
`import maigret` ก็ยังได้ไฟล์ที่พังนี้อยู่ดี

## ความสามารถเหล่านี้ย้ายไปอยู่ที่ไหน

`username_osint.py` ที่รากโปรเจกต์ — ใช้ **ฐานข้อมูลเว็บไซต์ของโปรเจกต์เอง**
(`resource/data.json`, 4,990 เว็บ ใช้ตรวจได้จริง 2,449 เว็บ) ซึ่งเป็นของมีค่า
จริงๆ ของไฟล์เหล่านี้ แล้วเขียนตัวตรวจใหม่บน `requests` + `ThreadPoolExecutor`
ที่โปรเจกต์ใช้อยู่แล้ว จึงไม่ต้องเพิ่ม dependency และเข้ากับ circuit breaker /
budget / cache เดิมได้ทันที

| ของเดิม | ของที่ใช้แทน |
|---|---|
| `sites.MaigretDatabase` | `username_osint.load_sites()`, `get_site()`, `search_sites()` |
| `checkings.check_site_for_username()` | `username_osint.check_site()`, `check_username()` |
| `checkings.process_site_result()` | `username_osint._decide()` |
| `maigret.utils.is_plausible_username()` | `username_osint.is_plausible_username()` |

ถ้าวันหนึ่งอยากใช้ maigret ตัวจริง: `pip install maigret` แล้ว `import maigret`
จะได้แพ็กเกจจริงแล้ว เพราะไม่มีไฟล์ที่รากบังอีกต่อไป
