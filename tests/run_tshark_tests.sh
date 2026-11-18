#!/usr/bin/env bash
# run_tshark_tests.sh - run the Lua post-dissectors inside tshark and check that they
# behave identically for the capture link types DLT 272 (Nordic nRF Sniffer),
# DLT 256 (LE LL with pseudo header) and DLT 251 (LE LL).
#
# Checks:
#   1. every variant: Info column is the same for all three link types and contains the
#      expected datagram text (see make_pcaps.py),
#   2. negative captures (wrong identifier, data channel PDU, truncated packet, other
#      advertising data length, no btle layer at all): the Info column equals the one
#      tshark prints WITHOUT any plugin, i.e. the dissectors return 0 and do not touch it,
#   3. tshark prints nothing that looks like a Lua error on stderr,
#   4. the repository cloned into a (fake) personal plugin folder, tests/ included, decodes the same
#      (Wireshark loads *.lua files recursively), and the startup prints no Lua load errors,
#   5. a real capture of the XN297L sniffer (tests/captures, DLT 256) is decoded in both modes,
#   6. no dissector assigns a global variable (luac5.4 -l shows no SETTABUP _ENV; skipped when
#      luac5.4 is not installed),
#   7. no tab characters in the source files (.editorconfig),
#   8. optional (COMPARE_MAIN=1): the dissectors from git branch main produce the same Info
#      column AND the same packet tree (tshark -V) as the current code, for every variant,
#      the real capture and a generated command sweep (all commands / lengths / variants,
#      see make_pcaps.py - generated on the fly, not committed as capture).
#
# Environment: TSHARK (default "tshark"), PYTHON (default "python3"), LUAC (default "luac5.4").
# Needs Wireshark with Lua support (Lua 5.3+ syntax is used by Crypt_Tools.lua).
# Usage: bash tests/run_tshark_tests.sh        exit code 0 = all passed

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
TSHARK="${TSHARK:-tshark}"
PYTHON="${PYTHON:-python3}"
LUAC="${LUAC:-luac5.4}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
checks=0

# check <description> <0 if ok>: bookkeeping of results
check() {
    checks=$((checks + 1))
    if [ "$2" -eq 0 ]; then
        echo "  ok   $1"
    else
        echo "  FAIL $1"
        failures=$((failures + 1))
    fi
}

# info_of <pcap> <dissector dir|none> : print the Info column of all frames, errors go to $WORK/err
# "-o gui.column.format" prints the Info column only; post-dissector changes are visible there
# (a plain "-T fields -e _ws.col.Info" would be evaluated before the post-dissectors ran).
info_of() {
    local pcap="$1" dir="$2" args=()
    if [ "$dir" != "none" ]; then
        local f
        for f in MouldKing PowerBox CaDA_RaceCar_PC CaDA_RaceCar_HS; do
            args+=(-X "lua_script:$dir/$f.lua")
        done
    fi
    "$TSHARK" -r "$pcap" "${args[@]}" -o 'gui.column.format:"Info","%i"' 2>>"$WORK/err"
}

# tree_of <pcap> <dissector dir> : full packet tree (tshark -V) with the dissectors of <dir>
tree_of() {
    local pcap="$1" dir="$2" args=() f
    for f in MouldKing PowerBox CaDA_RaceCar_PC CaDA_RaceCar_HS; do
        args+=(-X "lua_script:$dir/$f.lua")
    done
    "$TSHARK" -r "$pcap" "${args[@]}" -V 2>>"$WORK/err"
}

"$PYTHON" -I "$HERE/make_pcaps.py" "$WORK/pcaps" || { echo "pcap generation failed"; exit 2; }
: > "$WORK/err"

OLD_DIR=""
if [ "${COMPARE_MAIN:-0}" = "1" ]; then
    OLD_DIR="$WORK/main"
    mkdir -p "$OLD_DIR" && git -C "$REPO" archive main | tar -x -C "$OLD_DIR"
fi

echo "== positive variants: identical Info for DLT 272 / 256 / 251"
for info_file in "$WORK"/pcaps/*.info; do
    name="$(basename "$info_file" .info)"
    expected="$(cat "$info_file")"
    i272="$(info_of "$WORK/pcaps/${name}_dlt272.pcap" "$REPO")"
    i256="$(info_of "$WORK/pcaps/${name}_dlt256.pcap" "$REPO")"
    i251="$(info_of "$WORK/pcaps/${name}_dlt251.pcap" "$REPO")"
    echo "     $name: $i272"
    [[ "$i272" == *"$expected"* ]]; check "$name: DLT 272 contains expected text" $?
    [ "$i272" == "$i256" ];         check "$name: DLT 272 == DLT 256" $?
    [ "$i272" == "$i251" ];         check "$name: DLT 272 == DLT 251" $?
    if [ -n "$OLD_DIR" ]; then
        old272="$(info_of "$WORK/pcaps/${name}_dlt272.pcap" "$OLD_DIR")"
        [ "$i272" == "$old272" ];   check "$name: Info new == original (main) on DLT 272" $?
        # The MouldKing iOS frame raised a Lua error on main (see make_pcaps.py): its tree differs
        # on purpose and is checked in the sweep section instead.
        if [ "$name" != "mk_ios" ]; then
            [ "$(tree_of "$WORK/pcaps/${name}_dlt272.pcap" "$REPO")" == "$(tree_of "$WORK/pcaps/${name}_dlt272.pcap" "$OLD_DIR")" ]
            check "$name: packet tree (-V) new == original (main) on DLT 272" $?
        fi
    fi
done

echo "== negative captures: Info untouched (same as without plugins)"
for f in "$WORK"/pcaps/neg_*.pcap; do
    base="$(info_of "$f" none)"
    with="$(info_of "$f" "$REPO")"
    [ "$base" == "$with" ]; check "$(basename "$f"): Info unchanged ($with)" $?
done

echo "== repository installed as personal plugin folder (fake HOME, incl. tests/)"
FAKE_HOME="$WORK/home"
PLUGIN_DIR="$FAKE_HOME/.local/lib/wireshark/plugins/brickcontroller2-dissector"
mkdir -p "$PLUGIN_DIR" && cp -r "$REPO"/. "$PLUGIN_DIR"/ && rm -rf "$PLUGIN_DIR/.git"
# info_installed <pcap>: Info column with the plugins loaded from the personal plugin folder only
info_installed() {
    HOME="$FAKE_HOME" "$TSHARK" -r "$1" -o 'gui.column.format:"Info","%i"' 2>>"$WORK/err_installed"
}
: > "$WORK/err_installed"
for info_file in "$WORK"/pcaps/*.info; do
    name="$(basename "$info_file" .info)"
    [ "$(info_installed "$WORK/pcaps/${name}_dlt272.pcap")" == "$(info_of "$WORK/pcaps/${name}_dlt272.pcap" "$REPO")" ]
    check "$name: installed plugin folder == -X lua_script" $?
done
HOME="$FAKE_HOME" "$TSHARK" -G plugins >/dev/null 2>>"$WORK/err_installed"
if grep -qi 'lua' "$WORK/err_installed"; then cat "$WORK/err_installed"; false; else true; fi
check "no Lua load errors with the installed plugin folder (tshark startup, -G plugins)" $?

echo "== real capture (XN297L sniffer, DLT 256)"
REAL="$REPO/tests/captures/bleadvert_xn297l_dlt256.pcapng"
EXPECT="Android - MouldKing - MK4.0/MK5.0 Connect"
n_x="$(info_of "$REAL" "$REPO" | grep -c "$EXPECT")"
n_i="$(info_installed "$REAL" | grep -c "$EXPECT")"
n_base="$(info_of "$REAL" none | grep -c "$EXPECT")"
echo "     frames with '$EXPECT': -X mode $n_x, installed folder $n_i, without plugins $n_base"
[ "$n_x" -eq 48 ];    check "real capture: 48 MouldKing frames decoded with -X lua_script" $?
[ "$n_i" -eq 48 ];    check "real capture: 48 MouldKing frames decoded from installed plugin folder" $?
[ "$n_base" -eq 0 ];  check "real capture: no MouldKing text without plugins" $?
if [ -n "$OLD_DIR" ]; then
    [ "$(info_of "$REAL" "$REPO")" == "$(info_of "$REAL" "$OLD_DIR")" ]
    check "real capture: Info new == original (main)" $?
    [ "$(tree_of "$REAL" "$REPO")" == "$(tree_of "$REAL" "$OLD_DIR")" ]
    check "real capture: packet tree (-V) new == original (main)" $?
fi

if [ -n "$OLD_DIR" ]; then
    echo "== command sweep (generated frames of all commands/lengths/variants) vs main"
    SWEEP="$WORK/pcaps/sweep_dlt272.pcap"
    decoded="$(info_of "$SWEEP" "$REPO" | grep -vc 'ADV_NONCONN_IND')"
    total="$("$TSHARK" -r "$SWEEP" 2>/dev/null | wc -l)"
    echo "     $decoded of $total sweep frames are decoded"
    [ "$decoded" -ge 150 ];  check "sweep: at least 150 frames are decoded (the sweep is still meaningful)" $?
    [ "$(info_of "$SWEEP" "$REPO")" == "$(info_of "$SWEEP" "$OLD_DIR")" ]
    check "sweep: Info new == original (main)" $?
    [ "$(tree_of "$SWEEP" "$REPO")" == "$(tree_of "$SWEEP" "$OLD_DIR")" ]
    check "sweep: packet tree (-V) new == original (main)" $?
    # MouldKing iOS: main raises a Lua error, the new code leaves the frames alone (bounds guard)
    IOS="$WORK/pcaps/sweep_mk_ios_dlt272.pcap"
    [ "$(info_of "$IOS" "$REPO")" == "$(info_of "$IOS" "$OLD_DIR")" ]
    check "sweep MouldKing iOS: Info new == original (main)" $?
    tree_of "$IOS" "$OLD_DIR" | grep -q "Lua Error"
    check "sweep MouldKing iOS: original (main) raises a Lua error (known bug)" $?
fi

echo "== no Lua errors in the packet tree"
# Lua errors in a post-dissector are NOT printed on stderr but added as "Lua Error" expert info
# to the tree, so decode everything (all variants, the sweeps, the real capture) with -V.
tree_errors=0
for f in "$WORK"/pcaps/*.pcap "$REAL"; do
    if tree_of "$f" "$REPO" 2>&1 | grep -q "Lua Error"; then
        echo "     Lua error in $(basename "$f")"; tree_errors=$((tree_errors + 1))
    fi
done
[ "$tree_errors" -eq 0 ]; check "no 'Lua Error' in any decoded packet" $?

echo "== no global variables in the Lua files"
# A global assignment compiles to SETTABUP on _ENV; tests/ is excluded (its stubs set globals on purpose).
if command -v "$LUAC" >/dev/null 2>&1; then
    leaks=0
    for f in "$REPO"/*.lua; do
        if "$LUAC" -l -p "$f" | grep -E 'SETTABUP.*_ENV' >"$WORK/leak"; then
            echo "     global assignment in $(basename "$f"):"; sed 's/^/       /' "$WORK/leak"; leaks=$((leaks + 1))
        fi
    done
    [ "$leaks" -eq 0 ]; check "no global variable assignments in the dissector/helper modules" $?
else
    echo "  skip luac5.4 not found (set LUAC=/path/to/luac5.4): global variable check not run"
fi

echo "== code style (.editorconfig)"
# Only spaces for indentation: no tab characters in the Lua, Python and shell files.
if grep -lP '\t' "$REPO"/*.lua "$REPO"/tests/*.lua "$REPO"/tests/*.py "$REPO"/tests/*.sh; then false; else true; fi
check "no tab characters in .lua / .py / .sh files" $?

echo "== no Lua errors on stderr"
if grep -qiE 'lua|error|traceback|runtime' "$WORK/err"; then
    cat "$WORK/err"; false
else
    true
fi
check "stderr clean" $?

echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
