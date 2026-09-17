#!/usr/bin/env python3
# patch_engine_arm64e_pac.py — 给 roothide/arm64e 引擎的 fishhook 打 PAC 补丁
#
# 背景
# ----
# vendor 的闭源引擎 decrypt_helper.dylib 用 fishhook 重绑定 C 符号（crypto/文件/
# dladdr 等）。在 arm64e（A12+ 系统 App，带指针认证 PAC）上，它写进 __auth_got 槽
# 的必须是「用槽地址签过名的指针」，否则调用点的 `BRAA X16,X17` 认证失败 → SIGSEGV。
#
# 引擎里有两条重绑定实现：
#   1) rebind_symbols_for_image 内联的 chained-fixup 遍历（作者写了 arm64e 签名，
#      但 key/discriminator 是从「运行时已被 dyld 解析过的槽」里 vm_read 再当成
#      chained-fixup 记录去解析，取到的是垃圾）；
#   2) perform_rebinding_with_section（stock fishhook，直接写裸指针、完全没签名）。
#      引擎对自己这个 image 走的正是第 2 条，所以是崩溃的直接原因。
#
# 正确 schema（由 pristine chained-fixup 记录 0xc009...0061 与设备实测确认）：
#   __auth_got 函数槽 = key IA、地址分散(addrDiv=1)、discriminator=0
#   → 写入 = pacia(strip(replacement), &槽)               （配 auth-stub 的 BRAA X16,X17）
#   → 存原函数 = pacia(strip(slot_value), 0)              （配 hook 里调 orig 的 BLRAAZ）
#   → 存原函数只存一次（*replaced 仍为 0 时），防止多趟重绑把 orig 覆盖成 hook 自身。
#
# 本脚本对两条路径都打补丁：
#   * 路径 1 就地改（有富余槽位）；
#   * 路径 2 槽地址是内联算的（[X20,X19,LSL#3]），塞不下，用 __TEXT 头部零填充里的
#     代码洞做跳板。
#
# 补丁位点用「唯一指令序列」定位（不写死绝对地址），每处都带原始字节断言：
# 引擎一旦升级、字节对不上，脚本立即中止并提示需要重新推导，绝不静默改错。
#
# 用法：
#   python3 tools/patch_engine_arm64e_pac.py [引擎路径]           # 就地打补丁（默认 vendor roothide）
#   python3 tools/patch_engine_arm64e_pac.py -o 输出.dylib 输入.dylib
#   python3 tools/patch_engine_arm64e_pac.py --check [引擎路径]   # 只检测是否已打补丁
#
# 依赖：lipo（Xcode）、ldid（brew install ldid）。

import argparse
import os
import struct
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ENGINE = os.path.join(REPO, "vendor", "dylib", "roothide", "decrypt_helper.dylib")

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def le(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def run(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---- ARM64 指令编码助手 ---------------------------------------------------

def enc_b(delta):
    assert delta % 4 == 0
    imm = (delta // 4) & 0x03FFFFFF
    return 0x14000000 | imm


def enc_cbnz_x(rt, delta):
    assert delta % 4 == 0
    imm19 = (delta // 4) & 0x7FFFF
    return 0xB5000000 | (imm19 << 5) | (rt & 0x1F)


NOP = 0xD503201F
XPACI = lambda rd: 0xDAC143E0 | (rd & 0x1F)
PACIZA = lambda rd: 0xDAC123E0 | (rd & 0x1F)
PACIA = lambda rd, rn: 0xDAC10000 | ((rn & 0x1F) << 5) | (rd & 0x1F)
LDR_X_reg0 = lambda rt, rn: 0xF9400000 | ((rn & 0x1F) << 5) | (rt & 0x1F)      # LDR Xt,[Xn]
STR_X_reg0 = lambda rt, rn: 0xF9000000 | ((rn & 0x1F) << 5) | (rt & 0x1F)      # STR Xt,[Xn]
LDR_X_regoff8 = lambda rt, rn, rm: 0xF8607800 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rt & 0x1F)  # LDR Xt,[Xn,Xm,LSL#3]
STR_X_regoff8 = lambda rt, rn, rm: 0xF8207800 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rt & 0x1F)  # STR Xt,[Xn,Xm,LSL#3]
ADD_X_lsl3 = lambda rd, rn, rm: 0x8B000000 | ((rm & 0x1F) << 16) | (3 << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)  # ADD Xd,Xn,Xm,LSL#3


# ---- 位点锚（24/32 字节唯一指令序列）+ 期望改动 ---------------------------
# 每个锚是一段原始字节；find 必须命中且仅命中一次。

ANCHOR_WALK_SIGN = bytes.fromhex(
    "ea000034"  # CBZ  W10, +0x1C
    "f10240f9"  # LDR  X17,[X23]
    "103d4092"  # AND  X16,X8,#0xFFFF
    "3f090071"  # CMP  W9,#2
    "c1000054"  # B.NE +0x18
    "110ac1da"  # PACDA X17,X16
)
ANCHOR_WALK_SAVE = bytes.fromhex(
    "c90240f9"  # LDR  X9,[X22]
    "ea0240f9"  # LDR  X10,[X23]
    "3f010aeb"  # CMP  X9,X10
    "60000054"  # B.EQ +0xC
    "e943c1da"  # XPACI X9
    "090100f9"  # STR  X9,[X8]
)
ANCHOR_PERF_SAVE = bytes.fromhex(
    "e80a40f9"  # LDR  X8,[X23,#0x10]
    "f40340f9"  # LDR  X20,[SP,#0]
    "c80000b4"  # CBZ  X8, +0x18   (loc_ret)
    "897a73f8"  # LDR  X9,[X20,X19,LSL#3]
    "ea0640f9"  # LDR  X10,[X23,#8]
    "3f010aeb"  # CMP  X9,X10
    "40000054"  # B.EQ +0x8
    "090100f9"  # STR  X9,[X8]
)
ANCHOR_PERF_WRITE = bytes.fromhex(
    "c80240f9"  # LDR  X8,[X22]
    "09038052"  # MOV  W9,#0x18
    "e0f6ff35"  # CBNZ W0, loc_fail
    "6823099b"  # MADD X8,X27,X9,X8
    "080540f9"  # LDR  X8,[X8,#8]
    "887a33f8"  # STR  X8,[X20,X19,LSL#3]
)

# STR X17,[SP,#0x40]（walker 写入路径的落地槽），作为额外一致性断言
STR_X17_SP40 = 0xF90023F1


def find_unique(data, anchor, label):
    pos = data.find(anchor)
    if pos < 0:
        raise SystemExit(f"[x] 未找到位点 {label}（引擎版本/布局可能已变，需重新推导补丁）")
    if data.find(anchor, pos + 1) >= 0:
        raise SystemExit(f"[x] 位点 {label} 命中多次，锚不唯一，拒绝打补丁")
    return pos


def parse_macho(data):
    """返回 (sizeofcmds, text_fileoff, text_vaddr, text_seg_vmaddr, text_seg_fileoff)"""
    if u32(data, 0) != MH_MAGIC_64:
        raise SystemExit("[x] 不是 arm64e thin Mach-O（magic 不符）")
    ncmds = u32(data, 16)
    sizeofcmds = u32(data, 20)
    off = 32
    text_off = text_va = seg_vm = seg_fo = None
    for _ in range(ncmds):
        cmd = u32(data, off)
        cmdsize = u32(data, off + 4)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].split(b"\0")[0]
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            nsects = u32(data, off + 64)
            so = off + 72
            for _s in range(nsects):
                sname = data[so:so + 16].split(b"\0")[0]
                if segname == b"__TEXT" and sname == b"__text":
                    text_va = struct.unpack_from("<Q", data, so + 32)[0]
                    text_off = u32(data, so + 48)
                    seg_vm, seg_fo = vmaddr, fileoff
                so += 80
        off += cmdsize
    if text_off is None:
        raise SystemExit("[x] 找不到 __TEXT,__text 段")
    return sizeofcmds, text_off, text_va, seg_vm, seg_fo


def find_cave(data, sizeofcmds, text_off, need):
    """在 load commands 之后、__text 之前的零填充里找 >=need 字节、16 字节对齐的代码洞。

    关键：必须紧贴 __text（padding 尾部）放，远离 load commands。
    因为 lipo -thin 会剥掉 LC_CODE_SIGNATURE，本脚本按剥离后的（较短）load
    commands 选洞；随后 ldid -S 会把签名 load command 加回来、令 load commands
    重新变长，若代码洞挨着 LC 区就会被覆盖（实测崩在 SIGILL）。所以从 __text 往
    低地址扫，取最靠近 __text 的零区，并对 LC 末尾留足余量。"""
    lo = (32 + sizeofcmds + 15) & ~15
    lo = max(lo, ((32 + sizeofcmds) + 0x400 + 15) & ~15)  # 给重签名增长的 load commands 留 1KB 余量
    o = (text_off - need) & ~0xF
    while o >= lo:
        if data[o:o + need] == b"\0" * need:
            return o
        o -= 16
    raise SystemExit(f"[x] __TEXT 头部零填充不足以容纳 {need} 字节代码洞（下限 0x{lo:x}，__text 0x{text_off:x}）")


def is_patched(data):
    pos = data.find(ANCHOR_WALK_SIGN)
    if pos >= 0:
        return False  # 锚在 = 未打补丁
    # 补丁后 walker-sign 处首指令应为 NOP
    return True


def patch_slice(data):
    data = bytearray(data)
    sizeofcmds, text_off, text_va, seg_vm, seg_fo = parse_macho(data)
    # __TEXT 内 fileoff -> vaddr 的换算（本类 dylib 通常 vmaddr==fileoff==0）
    delta_va = seg_vm - seg_fo

    def va(fo):
        return fo + delta_va

    # 定位四个位点
    w_sign = find_unique(data, ANCHOR_WALK_SIGN, "walker-sign")
    w_save = find_unique(data, ANCHOR_WALK_SAVE, "walker-save")
    p_save = find_unique(data, ANCHOR_PERF_SAVE, "perf-save")
    p_write = find_unique(data, ANCHOR_PERF_WRITE, "perf-write")

    # 一致性断言：walker 写入落地槽 STR X17,[SP,#0x40] 应在 w_sign+0x2C
    if u32(data, w_sign + 0x2C) != STR_X17_SP40:
        raise SystemExit("[x] walker-sign 落地槽 (STR X17,[SP,#0x40]) 断言失败，布局已变")

    # 代码洞：cave_save(7 条) + cave_write(5 条) = 48 字节
    cave = find_cave(data, sizeofcmds, text_off, 12 * 4)
    cave_save = cave
    cave_write = cave + 7 * 4

    def w(fo, val):
        data[fo:fo + 4] = le(val)

    # ---- 路径 1：walker 就地补丁 ----
    # sign：nop / (keep ldr x17,[x23]) / xpaci x17 / pacia x17,x22 / b -> STR(+0x2C)
    w(w_sign + 0x00, NOP)
    w(w_sign + 0x08, XPACI(17))
    w(w_sign + 0x0C, PACIA(17, 22))
    w(w_sign + 0x10, enc_b((w_sign + 0x2C) - (w_sign + 0x10)))
    # save：ldr x9,[x8] / cbnz x9,+0x14 / ldr x9,[x22] / xpaci x9 / paciza x9 / (keep str x9,[x8])
    w(w_save + 0x00, LDR_X_reg0(9, 8))
    w(w_save + 0x04, enc_cbnz_x(9, (w_save + 0x18) - (w_save + 0x04)))
    w(w_save + 0x08, LDR_X_reg0(9, 22))
    w(w_save + 0x0C, XPACI(9))
    w(w_save + 0x10, PACIZA(9))

    # ---- 路径 2：perform_rebinding_with_section 用代码洞跳板 ----
    ret_save = p_save + 0x20   # loc_ret（CBZ X8 的目标）
    ret_write = p_write + 0x18  # 原 STR 之后的 B loc_...
    # 位点改成跳到代码洞
    w(p_save + 0x0C, enc_b(va(cave_save) - va(p_save + 0x0C)))
    w(p_write + 0x14, enc_b(va(cave_write) - va(p_write + 0x14)))
    # cave_save
    w(cave_save + 0x00, LDR_X_reg0(9, 8))
    w(cave_save + 0x04, enc_cbnz_x(9, (cave_save + 0x18) - (cave_save + 0x04)))
    w(cave_save + 0x08, LDR_X_regoff8(9, 20, 19))
    w(cave_save + 0x0C, XPACI(9))
    w(cave_save + 0x10, PACIZA(9))
    w(cave_save + 0x14, STR_X_reg0(9, 8))
    w(cave_save + 0x18, enc_b(va(ret_save) - va(cave_save + 0x18)))
    # cave_write
    w(cave_write + 0x00, ADD_X_lsl3(9, 20, 19))
    w(cave_write + 0x04, XPACI(8))
    w(cave_write + 0x08, PACIA(8, 9))
    w(cave_write + 0x0C, STR_X_regoff8(8, 20, 19))
    w(cave_write + 0x10, enc_b(va(ret_write) - va(cave_write + 0x10)))

    return bytes(data), {
        "walker_sign": va(w_sign), "walker_save": va(w_save),
        "perf_save": va(p_save), "perf_write": va(p_write),
        "cave_save": va(cave_save), "cave_write": va(cave_write),
    }


def main():
    ap = argparse.ArgumentParser(description="给 roothide/arm64e 引擎的 fishhook 打 PAC 补丁")
    ap.add_argument("engine", nargs="?", default=DEFAULT_ENGINE, help="fat dylib 路径（默认 vendor roothide）")
    ap.add_argument("-o", "--output", help="输出路径（默认就地覆盖并保留 .pristine 备份）")
    ap.add_argument("--check", action="store_true", help="只检测是否已打补丁")
    args = ap.parse_args()

    engine = args.engine
    if not os.path.isfile(engine):
        raise SystemExit(f"[x] 找不到引擎: {engine}")

    for tool in ("lipo", "ldid"):
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            raise SystemExit(f"[x] 需要 {tool}")

    archs = subprocess.check_output(["lipo", "-archs", engine]).decode().split()
    if "arm64e" not in archs:
        raise SystemExit(f"[x] 引擎不含 arm64e 切片（archs={archs}）")

    with tempfile.TemporaryDirectory() as td:
        e_path = os.path.join(td, "arm64e.dylib")
        run("lipo", engine, "-thin", "arm64e", "-output", e_path)
        e_data = open(e_path, "rb").read()

        if args.check:
            print("PATCHED" if is_patched(e_data) else "PRISTINE", "-", engine)
            return

        if is_patched(e_data):
            raise SystemExit("[x] 引擎已打过补丁（walker-sign 锚缺失）；如需重打请从 pristine 引擎开始")

        patched, sites = patch_slice(e_data)
        open(e_path, "wb").write(patched)

        # 其余切片原样保留，仅替换 arm64e，然后 lipo 合并
        thin_paths = []
        create = []
        for a in archs:
            if a == "arm64e":
                thin_paths.append(e_path)
                create += [e_path]
            else:
                p = os.path.join(td, f"{a}.dylib")
                run("lipo", engine, "-thin", a, "-output", p)
                create += [p]

        out = args.output or engine
        if not args.output:
            bak = engine + ".pristine"
            if not os.path.exists(bak):
                open(bak, "wb").write(open(engine, "rb").read())
                print(f"[*] 已备份 pristine → {bak}")
        run("lipo", "-create", *create, "-output", out)
        run("ldid", "-S", out)

    print(f"[*] 打补丁完成 → {out}")
    for k, v in sites.items():
        print(f"      {k:12s} @ 0x{v:x}")
    print("[*] 位点：pacia(strip(replacement),&槽) 写入 / pacia(strip(slot),0) 存 orig / orig 只存一次")


if __name__ == "__main__":
    main()
