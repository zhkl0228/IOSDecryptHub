#!/bin/sh
# launchd 入口。rootHide 下直接 Program=jb 路径会 exit 78，
# postinst 改成 /bin/sh 执行本脚本。
# 签过名的 daemon 对 /usr/lib/IOSDecryptHub 是 EPERM；本脚本负责把
# staging 里已校验的引擎拷进目录，然后再跑 Mach-O（网络/解析）。
set -e
DIR=$(dirname "$0")
JBROOT=$(cd "$DIR/../../.." 2>/dev/null && pwd)
DAEMON="$DIR/IOSDecryptHubUpdated"
DEST="$DIR/decrypt_helper.dylib"
STAGE="/var/cache/com.iosdecrypthub"
NEW="$STAGE/decrypt_helper.dylib.new"
ROLLBACK="$STAGE/do_rollback"

mkdir -p "$STAGE" /var/log 2>/dev/null || true

# 沙盒目标读不到 /var/mobile/.../loader.plist；jb 这份才是注入门。
# rootHide 上签过名的 daemon 写 /usr/lib 是 EPERM，这里用 /bin/sh 拷。
sync_enabled() {
    PREFS="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
    CFGDIR="$DIR/config"
    CFG="$CFGDIR/enabledBundles.plist"
    mkdir -p "$CFGDIR" 2>/dev/null || true
    if [ -f "$PREFS" ]; then
        cp "$PREFS" "$CFG" 2>/dev/null || true
        chmod 0666 "$CFG" 2>/dev/null || true
        chmod 0777 "$CFGDIR" 2>/dev/null || true
        chown mobile:mobile "$CFGDIR" "$CFG" 2>/dev/null || true
    fi
}

sync_request() {
    REQ_REAL="/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
    for REQ_SRC in \
        "$JBROOT/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist" \
        "$JBROOT/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist" \
        "/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist" \
        "/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist" \
        "$DIR/config/updater.request.plist"; do
        [ -f "$REQ_SRC" ] || continue
        if grep -q '<key>action</key><string>none</string>' "$REQ_SRC" 2>/dev/null; then
            rm -f "$REQ_SRC" 2>/dev/null || true
            continue
        fi
        cp "$REQ_SRC" "$REQ_REAL" 2>/dev/null || true
        chown mobile:mobile "$REQ_REAL" 2>/dev/null || true
        chmod 0644 "$REQ_REAL" 2>/dev/null || true
        rm -f "$REQ_SRC" 2>/dev/null || true
    done
}

sync_state() {
    SRC="$JBROOT/var/log/com.iosdecrypthub.updater.state.plist"
    DST="$DIR/state.plist"
    [ -f "$SRC" ] || return 0
    cp "$SRC" "$DST" 2>/dev/null || true
    chmod 0644 "$DST" 2>/dev/null || true
}

sync_enabled
sync_request

apply_new() {
    [ -f "$NEW" ] || return 0
    if [ -f "$DEST" ]; then
        cp "$DEST" "$DEST.bak" || true
        chmod 0755 "$DEST.bak" 2>/dev/null || true
        if [ -f "$DIR/version.plist" ]; then
            cp "$DIR/version.plist" "$DIR/decrypt_helper.dylib.bak.plist" || true
        fi
    fi
    cp "$NEW" "$DEST"
    chmod 0755 "$DEST"
    chown root:wheel "$DEST" 2>/dev/null || true
    if [ -f "$STAGE/version.plist" ]; then
        cp "$STAGE/version.plist" "$DIR/version.plist"
        chmod 0644 "$DIR/version.plist"
    fi
    rm -f "$NEW"
}

if [ -f "$ROLLBACK" ] && [ -f "$DEST.bak" ]; then
    TMP="$DEST.tmp"
    rm -f "$TMP"
    mv "$DEST" "$TMP"
    mv "$DEST.bak" "$DEST"
    mv "$TMP" "$DEST.bak"
    if [ -f "$DIR/decrypt_helper.dylib.bak.plist" ] && [ -f "$DIR/version.plist" ]; then
        mv "$DIR/version.plist" "$DIR/version.plist.swap"
        mv "$DIR/decrypt_helper.dylib.bak.plist" "$DIR/version.plist"
        mv "$DIR/version.plist.swap" "$DIR/decrypt_helper.dylib.bak.plist"
    fi
    rm -f "$ROLLBACK"
fi

apply_new
"$DAEMON" || true
apply_new
sync_state
sync_enabled
