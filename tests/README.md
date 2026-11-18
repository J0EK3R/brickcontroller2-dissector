# Tests

* `test_ble_tools.lua` - pure Lua unit test of `BLE_Tools.lua` with stubbed Wireshark API
  (`lua5.4 tests/test_ble_tools.lua`, run from the repository root): link layer lookup and the
  shared helpers `matches`, `hex`, `describe`, `addPayloadTrees`.
* `make_pcaps.py` - writes identical advertising packets as DLT 272 / 256 / 251 captures
  (payloads encrypted with a Python port of `Crypt_Tools.lua`). Used by the shell test.
  It also writes a *command sweep* (`sweep_dlt272.pcap`): frames for every MouldKing / JIE-STAR /
  PowerBox / CaDA command, length and platform, generated on the fly (nothing of it is committed).
* `run_tshark_tests.sh` - loads all four dissectors into tshark and checks that the Info column
  is identical for all link types (`TSHARK=/path/to/tshark bash tests/run_tshark_tests.sh`).
  It also checks that nothing is a Lua error, that the repository works as installed plugin
  folder, that no dissector assigns a global variable (needs `luac5.4`, `LUAC=/path/to/luac5.4`
  if it is not in `PATH`; skipped otherwise) and that there are no tab characters.
  `COMPARE_MAIN=1` additionally decodes all variants, the real capture and the command sweep
  with the dissectors of branch `main` and requires the same Info column and the same packet tree
  (`tshark -V`). Use it for every refactoring: it proves that the visible output did not change.
  Wireshark must be built with Lua 5.3 or newer (Wireshark 4.4 or newer).
