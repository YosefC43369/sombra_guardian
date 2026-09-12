#!/bin/sh
# docker-entrypoint.sh — สตาร์ท Tor (ถ้ามี) แล้วค่อยรันบอท
#
# ทำไมต้องมีไฟล์นี้: คำสั่ง /identity, /corporate, /search ฝั่ง dark web ต้องมี
# Tor SOCKS proxy ฟังอยู่ที่ 127.0.0.1:9050 ถ้าไม่มี ระบบจะขึ้น
# "Tor: ไม่พร้อมใช้งาน" แล้วค้นได้แต่เว็บเปิด สคริปต์นี้สตาร์ท Tor ให้ในคอนเทนเนอร์
# เดียวกันก่อน แล้ว exec บอทต่อ (exec เพื่อให้บอทเป็น PID 1 รับสัญญาณ stop ตรงๆ)
#
# ปิด Tor ได้ด้วย env  DISABLE_TOR=1  (เช่นเมื่อชี้ไป Tor ตัวนอกผ่าน
# TOR_SOCKS_HOST/TOR_SOCKS_PORT อยู่แล้ว)

set -e

TOR_PORT="${TOR_SOCKS_PORT:-9050}"

if [ "${DISABLE_TOR:-0}" != "1" ] && command -v tor >/dev/null 2>&1; then
    echo "[entrypoint] เริ่ม Tor ที่พอร์ต ${TOR_PORT} ..."
    # ใช้ไดเรกทอรีข้อมูลที่ผู้ใช้ปัจจุบันเขียนได้ (คอนเทนเนอร์รันเป็น non-root)
    TOR_DATA="${TOR_DATA_DIR:-/tmp/tor-data}"
    mkdir -p "$TOR_DATA"
    tor --SocksPort "127.0.0.1:${TOR_PORT}" \
        --DataDirectory "$TOR_DATA" \
        --Log "notice stdout" \
        --RunAsDaemon 0 &
    TOR_PID=$!
    echo "[entrypoint] Tor PID=${TOR_PID} — บอทจะตรวจเองว่าเชื่อมต่อได้เมื่อไหร่"
else
    if [ "${DISABLE_TOR:-0}" = "1" ]; then
        echo "[entrypoint] DISABLE_TOR=1 — ข้ามการสตาร์ท Tor ในคอนเทนเนอร์"
    else
        echo "[entrypoint] ไม่พบคำสั่ง tor — ค้นได้เฉพาะเว็บเปิด"
        echo "[entrypoint] ถ้าต้องการ dark web: ติดตั้ง tor ใน image หรือชี้"
        echo "[entrypoint] TOR_SOCKS_HOST/TOR_SOCKS_PORT ไปที่ Tor ตัวนอก"
    fi
fi

exec python app.py
