#!/usr/bin/env bash
# Cross-compile from Linux/macOS/WSL/MSYS2 with mingw-w64. Output: SailHighSea-Firewall.exe
set -euo pipefail
cd "$(dirname "$0")"
CC=${CC:-x86_64-w64-mingw32-gcc}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
VER=${1:-0.2.0}
DISPLAY_VER=${2:-$VER}   # shown in the title bar (e.g. 0.1.1-dev.5)
IFS=. read -r MA MI PA <<<"$VER"
$WINDRES -DAPP_VERSION_STR="\\\"$VER\\\"" -DAPP_VERSION_NUM="${MA:-0},${MI:-0},${PA:-0},0" -O coff app.rc -o app_res.o
$CC -municode -mwindows -Os -s -Wall -Wextra -Wno-unused-parameter -Wno-cast-function-type \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -static \
    -DAPP_VERSION="L\"$DISPLAY_VER\"" \
    main.c app_res.o -o SailHighSea-Firewall.exe \
    -lfwpuclnt -lcomctl32 -lcomdlg32 -lshell32 -lole32 -luxtheme -ldwmapi -luser32 -lgdi32 -ladvapi32 -lsecur32 -lgdiplus
rm -f app_res.o
ls -l SailHighSea-Firewall.exe
