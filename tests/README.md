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
  folder, that the `ProtoField`s carry the decoded values and work in display filters, that no dissector assigns a global variable (needs `luac5.4`, `LUAC=/path/to/luac5.4`
  if it is not in `PATH`; skipped otherwise) and that there are no tab characters.
  `COMPARE_MAIN=1` additionally decodes all variants, the real capture and the command sweep
  with the dissectors of branch `main` and requires the same Info column and the same packet tree
  (`tshark -V`). Use it for every refactoring: it proves that the visible output did not change.
  The verified iOS rows are decoded by the current code only (main does not know them): a generated iOS sweep
  (`sweep_ios_dlt272.pcap`, all identifiers / commands) must be decoded completely and is checked
  separately (`COMPARE_MAIN=1` requires that main decodes none of it).
  Optional local check against a real iOS capture, which is **not** part of the repository: set
  `IOS_CAPTURE=/path/to/bleadvert.iOS.pcapng` (default `../../tasks/022-ios-variants/bleadvert.iOS.pcapng` relative
  to the repository, skipped when the file does not exist). It prints how many frames were decoded as
  `iOS - MouldKing/JIE-STAR` and `iOS - PowerBox`, requires no decryption failures, no generic
  "8-Byte Payload" text, no CaDA claim and no Lua error. `IOS_EXPECT_MK` / `IOS_EXPECT_PB` optionally pin the
  exact counts. No packet of the capture is stored in the repository.
  Wireshark must be built with Lua 5.3 or newer (Wireshark 4.4 or newer).
