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
#   7. the ProtoFields (mouldking.cmd, cada_hs.seq, ...) carry the decoded values and work in filters,
#   8. no tab characters in the source files (.editorconfig),
#   9. optional (COMPARE_MAIN=1): the dissectors from git branch main produce the same Info
#      column AND the same packet tree (tshark -V) as the current code, for every variant,
#      the real capture and a generated command sweep (all commands / lengths / variants,
#      see make_pcaps.py - generated on the fly, not committed as capture). Use it against a main that
#      does not contain the change under test.
#  10. the verified iOS rows: a generated iOS sweep (MouldKing / JIE-STAR / PowerBox) is decoded completely,
#      same Info and tree as main with COMPARE_MAIN=1, and (optional) a local iOS capture is decoded without leftovers; the
#      full capture is NOT part of the repository (a small selection is, see 11): set IOS_CAPTURE=/path/to/bleadvert.iOS.pcapng (default:
#      ../../tasks/022-ios-variants/bleadvert.iOS.pcapng next to the repository, skipped when missing).
#  11. real BrickController2 telegrams (tests/captures/real_android.pcapng, real_ios.pcapng): the Info column
#      equals the golden files real_*.info in -X mode and from the installed plugin folder, plus ProtoField values.
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
        [ "$(tree_of "$WORK/pcaps/${name}_dlt272.pcap" "$REPO")" == "$(tree_of "$WORK/pcaps/${name}_dlt272.pcap" "$OLD_DIR")" ]
        check "$name: packet tree (-V) new == original (main) on DLT 272" $?
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

echo "== real BrickController2 telegrams (Android + iOS, tests/captures/real_*.pcapng) vs golden Info files"
# The golden files hold the expected Info column, one line per frame (same order as the capture).
for plat in android ios; do
    cap="$REPO/tests/captures/real_$plat.pcapng"
    golden="$(cat "$REPO/tests/captures/real_$plat.info")"
    n_frames="$("$TSHARK" -r "$cap" 2>>"$WORK/err" | wc -l)"
    [ "$(info_of "$cap" "$REPO")" == "$golden" ]; check "real_$plat: Info == golden file, -X lua_script ($n_frames frames)" $?
    [ "$(info_installed "$cap")" == "$golden" ];  check "real_$plat: Info == golden file, installed plugin folder" $?
    # every frame of these captures is a BrickController2 telegram: none may stay undecoded
    [ "$(grep -c ' - ' <<< "$golden")" -eq "$n_frames" ]
    check "real_$plat: every frame is a decoded telegram (no leftover radio frames)" $?
    [ "$(info_of "$cap" none | grep -c ' - ')" -eq 0 ]; check "real_$plat: nothing decoded without the plugins" $?
done
# every device family appears in the golden files (the golden files pin the decoding per family)
for fam in "iOS - MouldKing - MK2.0/MK3.0/MK4.0D/MK8.0 Command" "iOS - MouldKing - MK3.8 Command" \
           "iOS - MouldKing - MK4.0/MK5.0 Command" "iOS - MouldKing - MK6.0[1] Command" \
           "iOS - JIE-STAR - JIE-STAR 8CH[1] Command" "iOS - JIE-STAR - JIE-STAR 4CH[1] Command" \
           "iOS - JIE-STAR - JIE-STAR 4CH[2] Command" "iOS - JIE-STAR - JIE-STAR 4CH[3] Command" \
           "iOS - PowerBox - Command" "iOS - PowerBox - Connect" \
           "Android - MouldKing - MK3.8 Command" "Android - MouldKing - MK4.0/MK5.0 Command" \
           "Android - MouldKing - MK6.0[3] Command" "Android - JIE-STAR - JIE-STAR 8CH[1] Command" \
           "Android - JIE-STAR - JIE-STAR 4CH[2] Command" "Android - PowerBox - Command" "Android - CaDA - Control"; do
    grep -q -F -- "$fam" "$REPO"/tests/captures/real_ios.info "$REPO"/tests/captures/real_android.info; check "golden files contain: $fam" $?
done
if [ -n "$OLD_DIR" ]; then
    A="$REPO/tests/captures/real_android.pcapng"
    [ "$(info_of "$A" "$REPO")" == "$(info_of "$A" "$OLD_DIR")" ]; check "real_android: Info new == original (main)" $?
    [ "$(tree_of "$A" "$REPO")" == "$(tree_of "$A" "$OLD_DIR")" ]; check "real_android: packet tree (-V) new == original (main)" $?
    I="$REPO/tests/captures/real_ios.pcapng"
    [ "$(info_of "$I" "$REPO")" == "$(info_of "$I" "$OLD_DIR")" ]; check "real_ios: Info new == original (main)" $?
    [ "$(tree_of "$I" "$REPO")" == "$(tree_of "$I" "$OLD_DIR")" ]; check "real_ios: packet tree (-V) new == original (main)" $?
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
fi

echo "== iOS sweep (verified iOS rows: all MouldKing / JIE-STAR identifiers and PowerBox shape B)"
IOS="$WORK/pcaps/sweep_ios_dlt272.pcap"
read -r want_mk want_pb < "$WORK/pcaps/sweep_ios.counts"
ios_info="$(info_of "$IOS" "$REPO")"
# PowerBox shows unknown commands as "iOS - Unknown - unknown - 0x.."; MouldKing as "iOS - Unknown - Unknown - ..".
n_pb="$(grep -cE 'iOS - (PowerBox - |Unknown - unknown - 0x)' <<< "$ios_info")"
n_mk="$(( $(grep -c 'iOS - ' <<< "$ios_info") - n_pb ))"
echo "     $n_mk MouldKing/JIE-STAR frames (expected $want_mk), $n_pb PowerBox frames (expected $want_pb)"
[ "$n_mk" -eq "$want_mk" ]; check "iOS sweep: every MouldKing / JIE-STAR frame is decoded as iOS - MouldKing/JIE-STAR" $?
[ "$n_pb" -eq "$want_pb" ]; check "iOS sweep: every shape B frame is decoded as iOS - PowerBox" $?
! grep -q "Decryption failed" <<< "$ios_info"; check "iOS sweep: no decryption failure" $?
if [ -n "$OLD_DIR" ]; then
    [ "$(info_of "$IOS" "$REPO")" == "$(info_of "$IOS" "$OLD_DIR")" ]; check "iOS sweep: Info new == original (main)" $?
    [ "$(tree_of "$IOS" "$REPO")" == "$(tree_of "$IOS" "$OLD_DIR")" ]; check "iOS sweep: packet tree (-V) new == original (main)" $?
fi

echo "== local iOS capture (optional, not part of the repository)"
IOS_CAPTURE="${IOS_CAPTURE:-$REPO/../../tasks/022-ios-variants/bleadvert.iOS.pcapng}"
if [ -f "$IOS_CAPTURE" ]; then
    cap_info="$(info_of "$IOS_CAPTURE" "$REPO")"
    n_mk="$(grep -cE 'iOS - (MouldKing|JIE-STAR) - ' <<< "$cap_info")"
    n_pb="$(grep -cE 'iOS - PowerBox - ' <<< "$cap_info")"
    n_pb_cmd="$(grep -cE 'iOS - PowerBox - (Connect|Command) ' <<< "$cap_info")"
    echo "     $n_mk MouldKing/JIE-STAR frames, $n_pb PowerBox frames ($n_pb_cmd of them Connect/Command)"
    [ "$n_mk" -gt 0 ] && [ "$n_pb" -gt 0 ]; check "iOS capture: MouldKing/JIE-STAR and PowerBox frames are decoded" $?
    # IOS_EXPECT_MK / IOS_EXPECT_PB: optional exact frame counts (printed above, passed in by the caller)
    if [ -n "${IOS_EXPECT_MK:-}" ]; then [ "$n_mk" -eq "$IOS_EXPECT_MK" ]; check "iOS capture: $IOS_EXPECT_MK MouldKing/JIE-STAR frames" $?; fi
    if [ -n "${IOS_EXPECT_PB:-}" ]; then [ "$n_pb" -eq "$IOS_EXPECT_PB" ]; check "iOS capture: $IOS_EXPECT_PB PowerBox frames" $?; fi
    ! grep -q "Decryption failed" <<< "$cap_info"; check "iOS capture: no decryption failure" $?
    ! grep -qE '8-Byte Payload|10-Byte Payload' <<< "$cap_info"; check "iOS capture: no undecoded 8-/10-Byte payload (no PowerBox command shown as generic payload)" $?
    ! grep -qi 'cada' <<< "$cap_info"; check "iOS capture: no CaDA dissector claims a frame" $?
    tree_of "$IOS_CAPTURE" "$REPO" | grep -q "Lua Error"; [ $? -ne 0 ]; check "iOS capture: no 'Lua Error' in the packet trees" $?
else
    echo "  skip iOS capture not found ($IOS_CAPTURE, set IOS_CAPTURE=...)"
fi

echo "== filterable ProtoFields (values of the variants, see make_pcaps.py)"
# field_of <pcap> <field> : value of a field with the dissectors of the repository loaded
field_of() {
    local args=() f
    for f in MouldKing PowerBox CaDA_RaceCar_PC CaDA_RaceCar_HS; do args+=(-X "lua_script:$REPO/$f.lua"); done
    "$TSHARK" -r "$1" "${args[@]}" -T fields -e "$2" 2>>"$WORK/err"
}
P="$WORK/pcaps"
[ "$(field_of "$P/mk_android_dlt272.pcap" mouldking.cmd)" == "0x66" ];     check "mouldking.cmd" $?
[ "$(field_of "$P/mk_android_dlt272.pcap" mouldking.id)" == "0x7ba7" ];    check "mouldking.id" $?
[ "$(field_of "$P/mk_android_dlt272.pcap" mouldking.platform)" == "Android" ]; check "mouldking.platform" $?
[ "$(field_of "$P/mk_android_dlt272.pcap" mouldking.data)" == "80808080" ]; check "mouldking.data" $?
[ "$(field_of "$P/mk_ios_dlt272.pcap" mouldking.platform)" == "iOS" ];     check "mouldking.platform (iOS)" $?
[ "$(field_of "$P/mk_ios_js_ee_dlt272.pcap" mouldking.manufacturer)" == "JIE-STAR" ]; check "mouldking.manufacturer (iOS JIE-STAR)" $?
[ "$(field_of "$P/powerbox_ios_dlt272.pcap" powerbox.platform)" == "iOS" ]; check "powerbox.platform (iOS)" $?
[ "$(field_of "$P/powerbox_ios_dlt272.pcap" powerbox.cmd)" == "0x40" ];    check "powerbox.cmd (iOS)" $?
[ "$(field_of "$P/powerbox_windows_dlt272.pcap" powerbox.cmd)" == "0x40" ]; check "powerbox.cmd" $?
[ "$(field_of "$P/powerbox_windows_dlt272.pcap" powerbox.platform)" == "Windows" ]; check "powerbox.platform" $?
[ "$(field_of "$P/cada_pc_android_dlt272.pcap" cada.cmd)" == "0x10" ];     check "cada.cmd" $?
[ "$(field_of "$P/cada_pc_android_dlt272.pcap" cada.id)" == "0x75" ];      check "cada.id" $?
[ "$(field_of "$P/cada_hs_android_dlt272.pcap" cada_hs.cmd)" == "0xbb" ];  check "cada_hs.cmd" $?
[ "$(field_of "$P/cada_hs_android_dlt272.pcap" cada_hs.device_id)" == "0xc1c9" ]; check "cada_hs.device_id (little endian)" $?
[ "$(field_of "$P/cada_hs_android_dlt272.pcap" cada_hs.seq)" == "0x05" ];  check "cada_hs.seq" $?
# real telegrams: values decoded from the real captures
RA="$REPO/tests/captures/real_android.pcapng"; RI="$REPO/tests/captures/real_ios.pcapng"
# vals_of <pcap> <field> : sorted unique values of a field on one line (frames without the field are skipped)
vals_of() { field_of "$1" "$2" | grep . | sort -u | tr '\n' ' '; }
[ "$(vals_of "$RA" mouldking.id)" == "0x7800 0x785f " ];                check "real_android: mouldking.id values" $?
[ "$(vals_of "$RI" mouldking.platform)" == "iOS " ];                    check "real_ios: mouldking.platform is iOS" $?
[ "$(vals_of "$RA" mouldking.manufacturer)" == "JIE-STAR MouldKing " ]; check "real_android: mouldking.manufacturer" $?
[ "$(vals_of "$RI" mouldking.cmd)" == "0x40 0x41 0x42 0x43 0x61 0x62 0x63 0x66 0x6d 0x7d 0x81 0xa4 0xaa 0xad 0xb1 " ]
check "real_ios: mouldking.cmd covers all families (0x40-0x43, 0x61-0x63, 0x66, 0x6d, 0x7d, 0x81, connect 0xa4/0xaa/0xad/0xb1)" $?
# the first frame is a Connect telegram (its data is not part of the Info), so compare the first Command frame
[ "$(field_of "$RI" mouldking.data | grep . | sed -n 2p)" == "$(grep -m1 -oE '[0-9a-f]{2}( [0-9a-f]{2})+$' "$REPO/tests/captures/real_ios.info" | tr -d ' ')" ]
check "real_ios: first Command mouldking.data equals the data bytes in the golden Info" $?
[ "$(vals_of "$RI" powerbox.cmd)" == "0x40 0xa4 " ];                    check "real_ios: powerbox.cmd values (command and connect)" $?
[ "$(vals_of "$RI" powerbox.platform)" == "iOS " ];                     check "real_ios: powerbox.platform" $?
[ "$(vals_of "$RA" powerbox.platform)" == "Android " ];                 check "real_android: powerbox.platform" $?
[ "$(field_of "$RA" cada.cmd | grep -c 0x13)" -eq 4 ];                 check "real_android: cada.cmd 0x13 in the four CaDA frames" $?
# a display filter on a decoded value (-Y) selects exactly the frame
[ "$("$TSHARK" -r "$P/mk_android_dlt272.pcap" -X "lua_script:$REPO/MouldKing.lua" -Y 'mouldking.cmd == 0x66' 2>>"$WORK/err" | wc -l)" -eq 1 ]
check "display filter mouldking.cmd == 0x66 matches" $?

echo "== no Lua errors in the packet tree"
# Lua errors in a post-dissector are NOT printed on stderr but added as "Lua Error" expert info
# to the tree, so decode everything (all variants, the sweeps, the real capture) with -V.
tree_errors=0
for f in "$WORK"/pcaps/*.pcap "$REAL" "$REPO"/tests/captures/real_*.pcapng; do
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
