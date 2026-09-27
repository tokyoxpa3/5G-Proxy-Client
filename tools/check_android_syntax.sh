#!/usr/bin/env bash
# 用**出貨的 NDK clang** 對 app/src/main/cpp 的所有 .c 做語法檢查（秒級、不連結）。
#
# 為什麼非做不可：本機（Linux VM 的 GCC / MinGW）與出貨用的 NDK clang 對 C11 atomics
# 等語法的寬鬆度不同 —— 「VM 上測試全綠」不代表 assembleRelease 編得過。
# 詳見 skill `android-native-change-verification`。
set -u

cd "$(dirname "$0")/.." || exit 1

GRADLE=app/build.gradle
NDK_VERSION=$(sed -n 's/.*ndkVersion[[:space:]]*"\([^"]*\)".*/\1/p' "$GRADLE" | head -1)
MIN_SDK=$(sed -n 's/.*minSdk[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$GRADLE" | head -1)
SDK_DIR=$(sed -n 's/^sdk\.dir=//p' local.properties | tr -d '\r' | head -1)

if [ -z "$NDK_VERSION" ] || [ -z "$MIN_SDK" ] || [ -z "$SDK_DIR" ]; then
  echo "無法從 $GRADLE / local.properties 取得 ndkVersion / minSdk / sdk.dir" >&2
  exit 2
fi

NDK_ROOT="$SDK_DIR/ndk/$NDK_VERSION"
PREBUILT=$(ls -d "$NDK_ROOT"/toolchains/llvm/prebuilt/* 2>/dev/null | head -1)
if [ -z "$PREBUILT" ]; then
  echo "找不到 NDK prebuilt: $NDK_ROOT/toolchains/llvm/prebuilt/*" >&2
  exit 2
fi

CLANG="$PREBUILT/bin/clang"
[ -x "$CLANG" ] || CLANG="$PREBUILT/bin/clang.exe"
if [ ! -x "$CLANG" ]; then
  echo "找不到 clang: $PREBUILT/bin" >&2
  exit 2
fi

echo "ndk=$NDK_VERSION minSdk=$MIN_SDK"
echo "clang=$CLANG"

SRCS=$(ls app/src/main/cpp/*.c)
COUNT=0
FAIL=0
for f in $SRCS; do
  COUNT=$((COUNT + 1))
  OUT=$("$CLANG" --target=aarch64-linux-android"$MIN_SDK" \
        --sysroot="$PREBUILT/sysroot" -std=c11 -Wall -Wextra -fsyntax-only \
        -I app/src/main/cpp "$f" 2>&1)
  if printf '%s\n' "$OUT" | grep -q "error:"; then
    echo "--- ERROR: $f"
    printf '%s\n' "$OUT" | grep "error:"
    FAIL=1
  fi
done

if [ "$FAIL" -ne 0 ]; then
  echo "FAILED"
  exit 1
fi
echo "OK: $COUNT files, no errors"
