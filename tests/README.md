# Tests

* `test_ble_tools.lua` - pure Lua unit test of `BLE_Tools.lua` with stubbed Wireshark API
  (`lua5.4 tests/test_ble_tools.lua`, run from the repository root).
* `make_pcaps.py` - writes identical advertising packets as DLT 272 / 256 / 251 captures
  (payloads encrypted with a Python port of `Crypt_Tools.lua`). Used by the shell test.
* `run_tshark_tests.sh` - loads all four dissectors into tshark and checks that the Info column
  is identical for all link types (`TSHARK=/path/to/tshark bash tests/run_tshark_tests.sh`,
  `COMPARE_MAIN=1` additionally compares with the dissectors of branch `main`).
  Wireshark must be built with Lua 5.3 or newer (Wireshark 4.4 or newer).
