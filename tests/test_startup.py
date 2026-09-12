"""รัน main() ของจริงทั้งหมด ยกเว้น run_polling() (ซึ่งต้องต่อ Telegram)
เป็นการจำลองการ deploy เพื่อจับ NameError/AttributeError ตอนบูต"""
import sys, os, tempfile, logging
WORK = tempfile.mkdtemp(prefix="startup-")
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(WORK)                      # ให้ bot.db ไปเกิดในที่ชั่วคราว ไม่เลอะ repo
for f in (".env",):
    pass
os.environ["BOT_TOKEN"] = "123456:AAdummytokenfortestingonly-not-real"
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

from dotenv import load_dotenv
load_dotenv(os.path.join(_ROOT, ".env"), override=False)
os.environ["BOT_TOKEN"] = "123456:AAdummytokenfortestingonly-not-real"

import app

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---- 1. บรรทัดที่ทำให้ deploy พัง ----
import config
try:
    config.log_startup_summary()
    check("config.log_startup_summary() ไม่ระเบิด (บรรทัดที่ deploy พัง)", True)
except Exception as e:
    check("config.log_startup_summary() ไม่ระเบิด (บรรทัดที่ deploy พัง)", False, repr(e))

check("resolve_image_model() มีจริงและคืนค่าได้",
      isinstance(config.resolve_image_model(), str) and config.resolve_image_model(),
      config.resolve_image_model())
check("resolve_image_model() เคารพ default", config.resolve_image_model() == config.DEFAULT_IMAGE_MODEL
      or os.getenv("GPT_IMAGE_MODEL"), config.resolve_image_model())

# api_key_source ต้องเจอคีย์ไม่ว่าจะมาจากชื่อไหน
for name in ("GPT_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
    saved = {n: os.environ.pop(n, None) for n in ("GPT_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")}
    os.environ[name] = "sk-dummy"
    got = config.api_key_source()
    check(f"api_key_source() รู้จักคีย์จาก {name}", got == name, got)
    os.environ.pop(name, None)
    for n, v in saved.items():
        if v is not None: os.environ[n] = v

# ---- 2. gemini เรียก resolve_image_model ได้จริง (path ของ /imagine) ----
import gemini, inspect
src = inspect.getsource(gemini.generate_image)
check("gemini.generate_image ใช้ config.resolve_image_model", "config.resolve_image_model()" in src)
check("config มี resolve_image_model ให้ gemini เรียก", hasattr(config, "resolve_image_model"))

# ---- 3. รัน main() ทั้งหมด ยกเว้น run_polling ----
started = {}
class FakeApp:
    def __init__(self): self.handlers = []; self.error_handlers = []
    def add_handler(self, h, *a, **k): self.handlers.append(h)
    def add_error_handler(self, h, *a, **k): self.error_handlers.append(h)
    def run_polling(self, *a, **k):
        started["polling"] = True; started["app"] = self
class FakeBuilder:
    def token(self, *a): return self
    def post_init(self, *a): return self
    def post_shutdown(self, *a): return self
    def build(self): return FakeApp()
app.ApplicationBuilder = lambda: FakeBuilder()

try:
    app.main()
    check("main() รันจนถึง run_polling ได้โดยไม่ crash", started.get("polling") is True)
except SystemExit as e:
    check("main() รันจนถึง run_polling ได้โดยไม่ crash", False, f"SystemExit: {e}")
except Exception as e:
    check("main() รันจนถึง run_polling ได้โดยไม่ crash", False, f"{type(e).__name__}: {e}")

# ---- 4. คำสั่งใหม่ถูกลงทะเบียนจริงตอนบูต ----
booted = started.get("app")
if booted is not None:
    cmds = set()
    for h in booted.handlers:
        for c in (getattr(h, "commands", None) or []):
            cmds.add(c)
    for want in ("search", "identity", "corporate", "imagine", "help"):
        check(f"/{want} ถูกลงทะเบียนตอนบูต", want in cmds, sorted(cmds))
    check("มี error handler ติดตั้งไว้", len(booted.error_handlers) >= 1)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
