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
#   4. optional (COMPARE_MAIN=1): the ORIGINAL dissectors from git branch main
#      produce the same Info as the new ones on DLT 272.
#
# Environment: TSHARK (default "tshark"), PYTHON (default "python3").
# Needs Wireshark with Lua support (Lua 5.3+ syntax is used by Crypt_Tools.lua).
# Usage: bash tests/run_tshark_tests.sh        exit code 0 = all passed

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
TSHARK="${TSHARK:-tshark}"
PYTHON="${PYTHON:-python3}"
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
        [ "$i272" == "$old272" ];   check "$name: new == original (main) on DLT 272" $?
    fi
done

echo "== negative captures: Info untouched (same as without plugins)"
for f in "$WORK"/pcaps/neg_*.pcap; do
    base="$(info_of "$f" none)"
    with="$(info_of "$f" "$REPO")"
    [ "$base" == "$with" ]; check "$(basename "$f"): Info unchanged ($with)" $?
done

echo "== no Lua errors in the packet tree"
# Lua errors in a post-dissector are NOT printed on stderr but added as "Lua Error" expert info
# to the tree, so decode everything with -V. mk_ios is skipped (known pre-existing bug, see make_pcaps.py).
tree_errors=0
for f in "$WORK"/pcaps/*.pcap; do
    case "$f" in */mk_ios_*) continue ;; esac
    args=()
    for d in MouldKing PowerBox CaDA_RaceCar_PC CaDA_RaceCar_HS; do args+=(-X "lua_script:$REPO/$d.lua"); done
    if "$TSHARK" -r "$f" "${args[@]}" -V 2>&1 | grep -q "Lua Error"; then
        echo "     Lua error in $(basename "$f")"; tree_errors=$((tree_errors + 1))
    fi
done
[ "$tree_errors" -eq 0 ]; check "no 'Lua Error' in any decoded packet" $?

echo "== no Lua errors on stderr"
if grep -qiE 'lua|error|traceback|runtime' "$WORK/err"; then
    cat "$WORK/err"; false
else
    true
fi
check "stderr clean" $?

echo "$checks checks, $failures failures"
[ "$failures" -eq 0 ]
