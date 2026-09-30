# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.multiarch — #10 Multi-architecture execution support (ตรวจ QEMU)

ตรวจว่าเครื่องนี้มี QEMU user-mode emulator สำหรับสถาปัตยกรรมใดบ้าง (aarch64/arm/
mips/riscv64/ppc64le) เพื่อจะรัน/วิเคราะห์เครื่องมือประเภท IoT/เฟิร์มแวร์ต่างสถาปัตยกรรม
ถ้าไม่มี → UNAVAILABLE พร้อมบอกวิธีเปิดใช้ (ไม่แกล้งว่ารันข้ามสถาปัตยกรรมได้)

หมายเหตุ: การ "รันจริงข้ามสถาปัตยกรรม" ต้องผูกกับ probe/sandbox เพิ่ม — ส่วนนั้นเป็น
roadmap ที่นี่ทำแค่ตรวจความพร้อมของ toolchain อย่างซื่อตรง
"""

import shutil

from ..model import CapabilityResult, CapabilityStatus

_QEMU = {
    "qemu-aarch64": "ARM64", "qemu-arm": "ARM", "qemu-mips": "MIPS",
    "qemu-mipsel": "MIPSEL", "qemu-riscv64": "RISC-V 64", "qemu-ppc64le": "PPC64LE",
    "qemu-x86_64": "x86-64",
}


def run(ctx) -> CapabilityResult:
    found = {arch: emu for emu, arch in _QEMU.items() if shutil.which(emu)}
    if not found:
        return CapabilityResult(
            "Multi-Arch Support", CapabilityStatus.UNAVAILABLE.value,
            "ไม่มี QEMU user-mode emulator ในเครื่องนี้",
            data={"requires": "apt install qemu-user-static (ให้ได้ qemu-aarch64/qemu-mips ฯลฯ)",
                  "note": "การรันข้ามสถาปัตยกรรมจริงต้องต่อกับ probe/sandbox เพิ่ม (roadmap)"})
    return CapabilityResult(
        "Multi-Arch Support", CapabilityStatus.OK.value,
        f"เครื่องนี้พร้อม emulate: {', '.join(sorted(found.keys()))}",
        data={"available": found,
              "note": "ตรวจความพร้อม toolchain แล้ว; การ execute ข้ามสถาปัตยกรรมใน sandbox = roadmap"})
