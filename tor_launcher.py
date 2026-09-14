"""
tor_launcher.py — ทำให้บอตมี Tor SOCKS proxy ใช้เองตอนบูต (สำหรับ /search dark web)

ทำไมต้องมี: บางโฮสต์ (เช่น FPS.ms และแพเนลตระกูล Pterodactyl) รัน `python app.py`
ตรง ๆ ในคอนเทนเนอร์ Python ที่ไม่มี root และ "ไม่ได้รัน" docker-entrypoint.sh ของเรา
ทำให้ Tor ไม่เคยถูกสตาร์ท /search ฝั่ง dark web จึงขึ้น "Tor: ไม่พร้อมใช้งาน" เสมอ

โมดูลนี้ให้บอตสตาร์ท Tor เองจากฝั่ง Python ตอนบูต โดยพยายามตามลำดับ (fail แล้วไปข้อถัดไป):
  1. ถ้า Tor เข้าถึงได้อยู่แล้ว (entrypoint สตาร์ทไว้ หรือชี้ไป Tor ตัวนอกผ่าน
     TOR_SOCKS_HOST/PORT) — ใช้เลย ไม่ทำอะไรเพิ่ม
  2. ใช้ tor binary ที่มีในเครื่อง (env TOR_BINARY, PATH, หรือ path มาตรฐาน)
  3. ดาวน์โหลด Tor Expert Bundle (ทางการของ Tor Project) ลงโฟลเดอร์ที่เขียนได้
     แล้วรันจากตรงนั้น — วิธีนี้ทำงานได้แม้โฮสต์ไม่มี tor และไม่มี root

ทุกขั้นเป็น best-effort: ถ้าล้มทั้งหมด บอตยังทำงานต่อได้ (ค้นเฉพาะเว็บเปิด) ไม่ crash

ตัวแปรแวดล้อมที่เกี่ยวข้อง:
  DISABLE_TOR=1            ปิดการจัดการ Tor ทั้งหมด
  SEARCH_USE_TOR=false     (เหมือน DISABLE_TOR ในแง่ไม่สตาร์ท)
  TOR_SOCKS_HOST/PORT      ปลายทาง SOCKS (ดีฟอลต์ 127.0.0.1:9050)
  TOR_BINARY=/path/to/tor  ระบุ tor binary เอง (เช่นอัปโหลดขึ้นเซิร์ฟเวอร์)
  TOR_AUTO_DOWNLOAD=1      อนุญาตให้ดาวน์โหลด Tor Expert Bundle (ดีฟอลต์เปิด)
  TOR_EXPERT_VERSION=...   เวอร์ชันที่จะดาวน์โหลด (ถ้าไม่ตั้ง full URL)
  TOR_DOWNLOAD_URL=...     URL เต็มของ tarball (override เวอร์ชัน/สถาปัตยกรรม)
  TOR_BOOTSTRAP_TIMEOUT=30 วินาทีที่รอให้พอร์ต SOCKS เปิด
"""
import os
import shutil
import tarfile
import tempfile
import logging
import platform
import subprocess
import time
import urllib.request

import nethealth

logger = logging.getLogger("modbot.tor")

# เก็บ handle ของ process ไว้ระดับโมดูล ไม่ให้ถูก GC/รีปเปอร์จนตายกลางทาง
_tor_process = None

# เวอร์ชันดีฟอลต์ของ Tor Expert Bundle (override ได้ด้วย env) — ถ้าเวอร์ชันนี้
# ไม่มีแล้วจะ 404 แล้วตกไป fallback พร้อม log บอกวิธีตั้ง TOR_EXPERT_VERSION/URL
_DEFAULT_EXPERT_VERSION = "13.5.7"
_ARCH_MAP = {
    "x86_64": "linux-x86_64", "amd64": "linux-x86_64",
    "aarch64": "linux-aarch64", "arm64": "linux-aarch64",
    "i686": "linux-i686", "i386": "linux-i686",
}


def _truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _is_local_host(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def _find_tor_binary():
    """คืน path ของ tor binary ที่รันได้ หรือ None — ไม่ดาวน์โหลด"""
    env = os.getenv("TOR_BINARY", "").strip()
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    found = shutil.which("tor")
    if found:
        return found
    for candidate in ("/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor",
                      "/bin/tor"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _download_url() -> str:
    override = os.getenv("TOR_DOWNLOAD_URL", "").strip()
    if override:
        return override
    version = os.getenv("TOR_EXPERT_VERSION", "").strip() or _DEFAULT_EXPERT_VERSION
    arch = _ARCH_MAP.get(platform.machine().lower(), "linux-x86_64")
    return (f"https://dist.torproject.org/torbrowser/{version}/"
            f"tor-expert-bundle-{arch}-{version}.tar.gz")


def _download_tor(dest_dir: str):
    """ดาวน์โหลด+แตก Tor Expert Bundle คืน (binary_path, lib_dir) หรือ (None, None)

    โครงสร้าง tarball: มีโฟลเดอร์ tor/ ที่บรรจุไบนารี tor และไลบรารี .so ร่วม —
    ต้องตั้ง LD_LIBRARY_PATH ให้ชี้โฟลเดอร์นั้นตอนรัน"""
    url = _download_url()
    os.makedirs(dest_dir, exist_ok=True)
    tarball = os.path.join(dest_dir, "tor-expert-bundle.tar.gz")
    logger.info("TOR: กำลังดาวน์โหลด Tor Expert Bundle จาก %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "sombra-guardian/1.0"})
    with urllib.request.urlopen(req, timeout=float(os.getenv("TOR_DOWNLOAD_TIMEOUT", "60"))) as resp:
        data = resp.read()
    with open(tarball, "wb") as f:
        f.write(data)
    # แตกอย่างปลอดภัย: กันไฟล์ที่ path หลุดออกนอก dest_dir (tar path traversal)
    with tarfile.open(tarball, "r:gz") as tf:
        base = os.path.realpath(dest_dir)
        for member in tf.getmembers():
            target = os.path.realpath(os.path.join(dest_dir, member.name))
            if not (target == base or target.startswith(base + os.sep)):
                raise ValueError(f"unsafe path in tarball: {member.name}")
        tf.extractall(dest_dir)
    # หา binary ชื่อ 'tor' ที่แตกออกมา
    for root, _dirs, files in os.walk(dest_dir):
        for name in files:
            if name == "tor":
                binary = os.path.join(root, name)
                try:
                    os.chmod(binary, 0o755)
                except OSError:
                    pass
                if os.access(binary, os.X_OK):
                    return binary, root
    return None, None


def _launch(binary: str, port: int, lib_dir=None):
    data_dir = os.getenv("TOR_DATA_DIR") or os.path.join(tempfile.gettempdir(), "tor-data")
    os.makedirs(data_dir, exist_ok=True)
    env = os.environ.copy()
    if lib_dir:
        env["LD_LIBRARY_PATH"] = lib_dir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    cmd = [
        binary,
        "--SocksPort", f"127.0.0.1:{port}",
        "--DataDirectory", data_dir,
        "--Log", "notice stdout",
        "--RunAsDaemon", "0",
    ]
    logger.info("TOR: สตาร์ท %s ที่พอร์ต %s (DataDirectory=%s)", binary, port, data_dir)
    return subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env
    )


def ensure_tor(bootstrap_timeout=None) -> bool:
    """พยายามทำให้ Tor SOCKS ใช้งานได้ คืน True ถ้าพอร์ตเข้าถึงได้ตอนจบ

    เรียกครั้งเดียวตอนบูต (จาก app.main()). ปลอดภัยเสมอ — ไม่ raise
    """
    global _tor_process

    if _truthy("DISABLE_TOR"):
        logger.info("TOR: DISABLE_TOR=1 — ข้ามการจัดการ Tor")
        return False
    if os.getenv("SEARCH_USE_TOR", "auto").strip().lower() in ("false", "0", "off", "no"):
        logger.info("TOR: SEARCH_USE_TOR ปิดอยู่ — ข้ามการสตาร์ท Tor")
        return False

    host = nethealth.TOR_SOCKS_HOST
    port = nethealth.TOR_SOCKS_PORT

    # 1) เข้าถึงได้อยู่แล้ว?
    if nethealth.tor_reachable(force=True):
        logger.info("TOR: เข้าถึงได้อยู่แล้วที่ %s:%s", host, port)
        return True

    # ชี้ไป Tor ตัวนอกที่ยังไม่ขึ้น — ไม่ควรพยายามสตาร์ทเองบนเครื่องนี้
    if not _is_local_host(host):
        logger.warning("TOR: ชี้ไป %s:%s (ตัวนอก) แต่ยังต่อไม่ได้ — ตรวจ Tor ปลายทาง", host, port)
        return False

    # เผื่อ entrypoint เพิ่งสตาร์ท tor แต่พอร์ตยังไม่ทันเปิด — รอสั้น ๆ ก่อนตัดสินใจสตาร์ทเอง
    grace = float(os.getenv("TOR_STARTUP_GRACE", "6"))
    grace_deadline = time.monotonic() + grace
    while time.monotonic() < grace_deadline:
        if nethealth.tor_reachable(force=True):
            logger.info("TOR: เข้าถึงได้ที่ %s:%s (มีตัวอื่นสตาร์ทให้)", host, port)
            return True
        time.sleep(1)

    # 2) หา tor binary
    binary, lib_dir = _find_tor_binary(), None

    # 3) ไม่มี binary — ลองดาวน์โหลด (best-effort)
    if not binary and _truthy("TOR_AUTO_DOWNLOAD", "1"):
        # ดีฟอลต์เก็บใน cwd (บน Pterodactyl/FPS.ms คือ /home/container ที่เขียน+รันได้)
        # ไม่ใช้ /tmp เพราะบางโฮสต์ mount /tmp แบบ noexec ทำให้รันไบนารีไม่ได้
        dest = os.getenv("TOR_DOWNLOAD_DIR") or os.path.join(os.getcwd(), ".tor-bin")
        try:
            binary, lib_dir = _download_tor(dest)
        except Exception as exc:
            logger.warning("TOR: ดาวน์โหลด Tor ไม่สำเร็จ (%s) — ตั้ง TOR_DOWNLOAD_URL/"
                           "TOR_EXPERT_VERSION หรืออัปโหลด tor แล้วตั้ง TOR_BINARY", exc)

    if not binary:
        logger.warning(
            "TOR: ไม่มี tor binary และดาวน์โหลดไม่ได้ — /search จะค้นเฉพาะเว็บเปิด "
            "วิธีแก้บนโฮสต์แบบไม่มี root (เช่น FPS.ms): (1) ตั้ง TOR_AUTO_DOWNLOAD=1 "
            "(ดีฟอลต์) ให้บอตโหลดเอง, (2) อัปโหลด tor แล้วตั้ง TOR_BINARY=/path/to/tor, "
            "หรือ (3) ชี้ TOR_SOCKS_HOST/TOR_SOCKS_PORT ไป Tor ตัวนอก"
        )
        return False

    # สตาร์ท + รอให้พอร์ต SOCKS เปิด
    try:
        _tor_process = _launch(binary, port, lib_dir)
    except Exception as exc:
        logger.warning("TOR: สตาร์ท Tor ไม่สำเร็จ (%s)", exc)
        return False

    timeout = bootstrap_timeout if bootstrap_timeout is not None else \
        float(os.getenv("TOR_BOOTSTRAP_TIMEOUT", "30"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _tor_process.poll() is not None:
            logger.warning("TOR: process ออกก่อนเวลา (code=%s) — ค้นเฉพาะเว็บเปิด",
                           _tor_process.returncode)
            return False
        if nethealth.tor_reachable(force=True):
            logger.info("TOR: พอร์ต SOCKS เปิดแล้วที่ 127.0.0.1:%s "
                        "(วงจรจะพร้อมใช้ภายในไม่กี่สิบวินาที)", port)
            return True
        time.sleep(2)

    logger.warning("TOR: พอร์ตยังไม่เปิดภายใน %.0fs — อาจกำลัง bootstrap อยู่ "
                   "บอตจะลองใหม่เองเมื่อมีการค้นครั้งถัดไป", timeout)
    return False
