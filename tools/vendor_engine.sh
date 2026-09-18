#!/usr/bin/env bash
# vendor_engine.sh — 从上游 GitHub Release 把闭源引擎 decrypt_helper.dylib vendor 进本仓库。
#
# 为什么需要这个脚本
# ------------------
# 引擎闭源、以 Release 附件分发。本 fork 要注入 arm64e 系统 App/daemon,必须要有 arm64e 切片;
# 而 arm64e 上 fishhook 的 PAC 会崩,得用 tools/patch_engine_arm64e_pac.py 打补丁(上游没有此补丁,
# 故其 Release 里的 arm64e 是未打补丁的原件)。所以不能直接用 Release 的单 arch dylib,而要:
#   1) 取 roothide .deb 里的 arm64+arm64e 胖引擎(唯一带 arm64e 的分发物);
#   2) 给 arm64e 切片打 PAC 补丁,合回胖引擎 → vendor/dylib/roothide/;
#   3) 另抽 arm64 切片 → vendor/dylib/rootless/。
#
# 产物(build_deb.sh 打包时会再 `ldid -S` 重签,故此处签名无关紧要;只看 Mach-O code):
#   vendor/dylib/roothide/decrypt_helper.dylib   arm64+arm64e(arm64e 已打 PAC 补丁)
#       —— 当前 rootless 与 roothide 两个包都复用这个胖引擎(见 build_deb.sh 的 build_variant:
#          rootless 的 ENGINE_VARIANT 也传 "roothide"),这样 Dopamine 等 rootless 也能注入 arm64e。
#   vendor/dylib/rootless/decrypt_helper.dylib   arm64
#       —— 当前 build 未使用(两个包都走 roothide 胖引擎),仅为与目录结构一致而一并更新。
#
# 用法:
#   tools/vendor_engine.sh <version> [owner/repo]
#     version   引擎版本,如 1.27.2(须与 Release tag v<version> 及引擎内嵌版本串一致)
#     repo      上游仓库,默认 decrypthub/IOSDecryptHub
#
# 依赖:gh(已登录)、dpkg-deb、lipo、ldid、python3
#
# 严谨保证:patch_engine_arm64e_pac.py 用「唯一指令序列 + 原始字节断言」定位补丁点,引擎一旦升级
# 到字节对不上就会中止(绝不静默改错),本脚本随之中止 —— 那说明 PAC 补丁位点需要按其提示重新推导。
#
# 完成后仍需手动:确认 Makefile VERSION=<version> → ./build_deb.sh <variant> → 设备重测。
set -euo pipefail

VER="${1:?用法: $0 <version> [owner/repo]（version 如 1.27.2）}"
REPO="${2:-decrypthub/IOSDecryptHub}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/vendor/dylib"
PAC="$ROOT/tools/patch_engine_arm64e_pac.py"
DEB="com.iosdecrypthub_${VER}_roothide.deb"

for t in gh dpkg-deb lipo ldid python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "[x] 需要 $t 但未找到"; exit 1; }
done
[ -f "$PAC" ] || { echo "[x] 缺 PAC 补丁工具: $PAC"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "[*] 下载 $DEB (Release v$VER @ $REPO)…"
gh release download "v$VER" -R "$REPO" -p "$DEB" --dir "$WORK" --clobber

echo "[*] 解包 .deb…"
dpkg-deb -x "$WORK/$DEB" "$WORK/x"
ENG="$(find "$WORK/x" -path '*usr/lib/IOSDecryptHub/decrypt_helper.dylib' -type f | head -1)"
[ -n "$ENG" ] || { echo "[x] .deb 里找不到 decrypt_helper.dylib"; exit 1; }

ARCHS="$(lipo -archs "$ENG")"
echo "[*] .deb 引擎:$(stat -f%z "$ENG") 字节  arch=$ARCHS"
case " $ARCHS " in *" arm64 "*) ;;  *) echo "[x] 引擎缺 arm64 切片"; exit 1;; esac
case " $ARCHS " in *" arm64e "*) ;; *) echo "[x] 引擎缺 arm64e 切片(roothide 必需)"; exit 1;; esac

EMB="$(strings "$ENG" | grep -oE '1\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')"
echo "[*] 引擎内嵌版本串:$EMB"
case " $EMB " in *" $VER "*) ;; *) echo "[x] 内嵌版本($EMB)与请求 $VER 不符,中止"; exit 1;; esac

mkdir -p "$VENDOR/roothide" "$VENDOR/rootless"

echo "[*] roothide:给 arm64e 打 PAC 补丁并合回胖引擎 → vendor/dylib/roothide/"
python3 "$PAC" -o "$VENDOR/roothide/decrypt_helper.dylib" "$ENG"
python3 "$PAC" --check "$VENDOR/roothide/decrypt_helper.dylib"

echo "[*] rootless:抽 arm64 切片 → vendor/dylib/rootless/"
lipo "$ENG" -thin arm64 -output "$VENDOR/rootless/decrypt_helper.dylib"
ldid -S "$VENDOR/rootless/decrypt_helper.dylib"

echo
echo "[✓] vendor 完成:"
for v in roothide rootless; do
    p="$VENDOR/$v/decrypt_helper.dylib"
    echo "    $v: $(stat -f%z "$p") 字节  arch=$(lipo -archs "$p")  ver=$(strings "$p" | grep -oE '1\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')"
done
echo
echo "[!] 后续手动:确认 Makefile VERSION=$VER → ./build_deb.sh rootless(或 roothide)→ 设备重测(arm64e 注入不崩、内存桥仍通)。"
