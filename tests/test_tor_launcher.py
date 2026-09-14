"""เทส tor_launcher.py — ตัวสตาร์ท Tor ฝั่ง Python (สำหรับโฮสต์ที่ไม่รัน entrypoint
เช่น FPS.ms) นำเข้าเฉพาะ tor_launcher + nethealth (stdlib) จึงรันได้ทุกที่
ไม่แตะเครือข่ายจริง — ใช้การ monkeypatch/ตั้ง env แทน
"""
import sys, os, stat, tempfile
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import tor_launcher as t
import nethealth

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))


def _clear_env(*names):
    for n in names:
        os.environ.pop(n, None)


# ---------- helpers ----------
check("is_local: 127.0.0.1/localhost", t._is_local_host("127.0.0.1") and t._is_local_host("localhost"))
check("is_local: external = False", not t._is_local_host("tor.example.com"))
check("_truthy", t._truthy("X_ON", "1") and not t._truthy("X_OFF", "0"))

# _candidate_urls: full override ชนะทุกอย่าง
_clear_env("TOR_EXPERT_VERSION")
os.environ["TOR_DOWNLOAD_URL"] = "https://example.test/tor.tar.gz"
cands = list(t._candidate_urls())
check("candidate_urls: full override ชนะและเป็นตัวเดียว",
      cands == ["https://example.test/tor.tar.gz"], cands)
_clear_env("TOR_DOWNLOAD_URL")

# pinned version ต้องอยู่ในผู้สมัคร และ URL ชี้โดเมนทางการ
# (ปิด discovery ที่แตะเน็ตไว้ เพื่อให้เทสไม่พึ่งเครือข่ายและเร็ว)
_orig_disc = t._discover_versions
t._discover_versions = lambda: []
os.environ["TOR_EXPERT_VERSION"] = "13.5.6"
try:
    cands = list(t._candidate_urls())
finally:
    t._discover_versions = _orig_disc
    _clear_env("TOR_EXPERT_VERSION")
check("candidate_urls: มี pinned version", any("13.5.6" in u for u in cands), cands[:3])
check("candidate_urls: ชี้โดเมน Tor ทางการ",
      all(u.startswith("https://dist.torproject.org/") for u in cands), cands[:3])
check("candidate_urls: มี fallback เวอร์ชันเริ่มต้น", any("14.0.1" in u for u in cands))

# _find_tor_binary: เคารพ TOR_BINARY เมื่อรันได้
fd, fake = tempfile.mkstemp(prefix="tor-fake-")
os.close(fd)
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
os.environ["TOR_BINARY"] = fake
check("find_binary: ใช้ TOR_BINARY ที่รันได้", t._find_tor_binary() == fake, t._find_tor_binary())
os.environ["TOR_BINARY"] = "/nonexistent/tor"
check("find_binary: path ไม่มีจริง -> ไม่ใช้", t._find_tor_binary() != "/nonexistent/tor")
_clear_env("TOR_BINARY")
os.remove(fake)


# ---------- ensure_tor: short-circuits ----------
os.environ["DISABLE_TOR"] = "1"
check("ensure_tor: DISABLE_TOR=1 -> False", t.ensure_tor() is False)
_clear_env("DISABLE_TOR")

os.environ["SEARCH_USE_TOR"] = "false"
check("ensure_tor: SEARCH_USE_TOR=false -> False", t.ensure_tor() is False)
os.environ["SEARCH_USE_TOR"] = "auto"

# already reachable -> True, ไม่พยายามสตาร์ท
_orig = nethealth.tor_reachable
nethealth.tor_reachable = lambda timeout=2.0, force=False: True
try:
    check("ensure_tor: reachable อยู่แล้ว -> True", t.ensure_tor() is True)
finally:
    nethealth.tor_reachable = _orig

# external host + ต่อไม่ได้ -> ไม่สตาร์ทเอง, คืน False เร็ว
_orig_host = nethealth.TOR_SOCKS_HOST
_orig2 = nethealth.tor_reachable
nethealth.TOR_SOCKS_HOST = "tor.example.com"
nethealth.tor_reachable = lambda timeout=2.0, force=False: False
try:
    check("ensure_tor: external host ต่อไม่ได้ -> False (ไม่สตาร์ทเอง)",
          t.ensure_tor() is False)
finally:
    nethealth.TOR_SOCKS_HOST = _orig_host
    nethealth.tor_reachable = _orig2

# local + ไม่มี binary + ปิดดาวน์โหลด + grace สั้น -> False อย่างสง่างาม (ไม่ crash)
_orig3 = nethealth.tor_reachable
nethealth.tor_reachable = lambda timeout=2.0, force=False: False
os.environ["TOR_AUTO_DOWNLOAD"] = "0"
os.environ["TOR_STARTUP_GRACE"] = "0"
try:
    check("ensure_tor: ไม่มี binary/ปิดโหลด -> False (graceful)", t.ensure_tor(bootstrap_timeout=1) is False)
finally:
    nethealth.tor_reachable = _orig3
    _clear_env("TOR_AUTO_DOWNLOAD", "TOR_STARTUP_GRACE")


# ---------- เลือกไบนารี: ต้องเลือก tor/tor (runtime) ไม่ใช่ debug/tor ----------
def _elf(mach_code):
    b = bytearray(20); b[0:4] = b"\x7fELF"; b[4] = 2; b[5] = 1
    b[18:20] = mach_code.to_bytes(2, "little")
    return bytes(b) + b"\x00" * 200

_host = t._host_machines()
_code = {"x86_64": 0x3E, "aarch64": 0xB7, "i686": 0x03, "arm": 0x28}
_mach = _code[list(_host)[0]] if len(_host) == 1 else 0x3E
import tempfile as _tf, shutil as _sh
_d = _tf.mkdtemp()
os.makedirs(os.path.join(_d, "debug")); os.makedirs(os.path.join(_d, "tor"))
open(os.path.join(_d, "debug", "tor"), "wb").write(_elf(_mach))
open(os.path.join(_d, "tor", "tor"), "wb").write(_elf(_mach))
open(os.path.join(_d, "tor", "libssl.so.3"), "wb").write(b"x")
_bin, _lib = t._pick_tor_binary(_d)
check("pick_binary: เลือก tor/tor ไม่ใช่ debug/tor",
      _bin == os.path.join(_d, "tor", "tor"), _bin)
check("pick_binary: lib_dir มี .so", _lib == os.path.join(_d, "tor"), _lib)

# arch ไม่ตรง -> ไม่เลือก (กัน Exec format error)
_d2 = _tf.mkdtemp(); os.makedirs(os.path.join(_d2, "tor"))
_wrong = 0xB7 if _mach != 0xB7 else 0x3E
open(os.path.join(_d2, "tor", "tor"), "wb").write(_elf(_wrong))
_b2, _l2 = t._pick_tor_binary(_d2)
check("pick_binary: arch ไม่ตรง -> (None, None)", _b2 is None and _l2 is None, (_b2, _l2))
_sh.rmtree(_d); _sh.rmtree(_d2)


print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
