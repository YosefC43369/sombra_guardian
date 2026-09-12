#!/usr/bin/env python3
"""รันไฟล์ test_*.py ทั้งหมดในโฟลเดอร์นี้แล้วสรุปผลรวม

เทสแต่ละไฟล์เป็นสคริปต์อิสระ (ตั้ง exit code 0/1 เอง) ไม่ต้องใช้ pytest
ต้องมี requests + beautifulsoup4 (อยู่ใน requirements.txt แล้ว)

    python tests/run_all.py
"""
import os
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    failed = []
    for name in files:
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, name)],
            capture_output=True, text=True,
        )
        summary = ""
        for line in proc.stdout.splitlines():
            if line.startswith("===="):
                summary = line.strip()
        status = "OK " if proc.returncode == 0 else "FAIL"
        print(f"{status} | {name:<28} {summary}")
        if proc.returncode != 0:
            failed.append(name)
            # แสดงบรรทัด FAIL ให้เห็นสาเหตุ
            for line in proc.stdout.splitlines():
                if line.startswith("FAIL |"):
                    print("       " + line)

    print(f"\n{len(files) - len(failed)}/{len(files)} test files passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
