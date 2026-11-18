# brickcontroller2-dissector

Wireshark Lua post-dissectors for the Bluetooth LE advertising datagrams of toy
remote-control systems: MouldKing, JieStar, CaDA (PC and HS type) and PowerBox.
The dissectors decrypt the payload and show the result in the Info column and as
additional items in the packet tree ("Android - MouldKing - ... Command - Cmd[66] ...").

## Installation

Copy or clone the **whole folder** (cloning the complete repository, including `tests/`, directly into the plugins directory is fine: the test script is inert inside Wireshark) into the Wireshark personal Lua plugins directory. All `.lua`
files are needed, including the helper modules `BLE_Tools.lua`, `Crypt_Tools.lua` and `CaDA_Tools.lua`.

| OS | Directory |
|---|---|
| Linux / macOS | `~/.local/lib/wireshark/plugins/` (older versions: `~/.config/wireshark/plugins`) |
| Windows | `%APPDATA%\Wireshark\plugins\` |

The exact path is shown in Wireshark under *Help > About Wireshark > Folders > Personal Lua Plugins*.
Restart Wireshark afterwards. With `tshark` the files can also be loaded one by one:

    tshark -r capture.pcap -X lua_script:MouldKing.lua -X lua_script:PowerBox.lua \
           -X lua_script:CaDA_RaceCar_PC.lua -X lua_script:CaDA_RaceCar_HS.lua

Wireshark must be built with Lua 5.3 or newer (Wireshark 4.4 or newer); `Crypt_Tools.lua` uses
Lua 5.3 bit operators.

## Supported captures

The dissectors work on every capture in which Wireshark's own `btle` dissector decodes the
packets, independent of the capture link type:

* Nordic nRF Sniffer for Bluetooth LE (DLT 272, `LINKTYPE_NORDIC_BLE`),
* our XN297L sniffer (DLT 256, `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`, see `Tools/xn297l-sniffer` in the
  bluetooth-protocols repository),
* plain LE Link Layer captures (DLT 251, `LINKTYPE_BLUETOOTH_LE_LL`),
* other sources that produce `btle` packets with the advertising access address (e.g. Ubertooth).

Only advertising channel packets are evaluated. Other frames are left untouched.

## How the packet offset is found

`BLE_Tools.lua` asks Wireshark for the `btle` field of the frame and re-bases it to a `Tvb` that starts
at the access address. All offsets in the dissectors are relative to it (advertising data starts at
offset 12) and the length checks use the advertising data length from the PDU header instead of the
frame length, so no capture-specific header size is hard coded any more.

## Code structure

Every dissector has the same layout: preamble (`package.path`) -> constants and tables -> helpers ->
`dissector` function -> `register_postdissector`. Device specific knowledge is **data**, not code:

| File | Content |
|---|---|
| `BLE_Tools.lua` | `getLinkLayer()` plus shared helpers: `matches` (identifier check from a `{offset, byte}` list), `hex`, `describe` (`Cmd[ad] ID[7b a7] ..` text), `addPayloadTrees` |
| `Crypt_Tools.lua` | RF payload encryption / decryption (whitening, CRC) |
| `CaDA_Tools.lua` | second encryption layer of the CaDA PC control block |
| `MouldKing.lua` | `VARIANTS` table (Android and iOS rows for the MouldKing / JieStar identifiers) and `COMMANDS` table (command byte -> name) |
| `PowerBox.lua` | `VARIANTS` table (Android / Windows / iOS) |
| `CaDA_RaceCar_PC.lua`, `CaDA_RaceCar_HS.lua` | device response plus `VARIANTS` table (Android / iOS) |

Adding a device:

* **new MouldKing command**: add one row to `COMMANDS` in `MouldKing.lua` (`length`, `manufacturer`,
  `name`, `kind = "connect"` or `"command"`, a sample datagram as comment);
* **new platform / app**: add one row to `VARIANTS` (`advLen`, identifying bytes in `pattern`,
  where the payload starts, decryption parameters).

The code style is described by `.editorconfig` (4 spaces, no tabs). Lua 5.3 or newer is required, the
native bit operators are used (there is no dependency on the `bit` library).

## iOS

iOS cannot send manufacturer data, so the BrickController2 app puts the encrypted payload into an AD
structure of type 0x03 (16-bit Service Class UUIDs) instead. The iOS rows were verified with a real
capture of an iOS phone (nRF52840 sniffer); decrypting with the same seed as on Android gave plausible
datagrams (known command bytes, checksum byte, constant device id, the same PowerBox datagrams as on Android).
The payload starts 2 bytes earlier than on Android, therefore the whitening header offset is 13 (Android: 15).

| Shape | Advertising data | Decoded by | Content |
|---|---|---|---|
| A | advLen 31: `02 01 1a` Flags, `1b 03` + 26 byte payload area | `MouldKing.lua` (iOS rows) | MouldKing MK2.0 .. MK8.0, MK3.8, MK4.0/5.0, MK6.0 and JIE-STAR (identifier `f9 08 49 22 ..`, ctx2 0x25), JIE-STAR 4CH[2] (identifier `c0 3d ca 8f ..`, ctx2 0x26), JIE-STAR 4CH[3] (identifier `d7 2e 4b eb ..`, ctx2 0x27) |
| B | advLen 28: `02 01 1a` Flags, `02 0a <dBm>` TX power, `15 03` + 20 byte payload area | `PowerBox.lua` (iOS row) | PowerBox connect (`a4`) and command (`40`) |

Shape A and B carry the same identifier bytes: the frame shape tells MouldKing/JIE-STAR (A) and PowerBox (B)
apart. The command bytes `a4` / `40` are JIE-STAR on shape A and PowerBox on shape B, exactly like the Android
frame shapes. Apple "Nearby Info" frames (advLen 17) in such captures are not BrickController2 and are ignored.

Not verified (no frames in the capture): the CaDA iOS rows and the older PowerBox iOS row with advLen 26 (it is kept
unchanged and marked as unverified in `PowerBox.lua`).

## Filterable fields

Besides the text in the packet tree every dissector declares `ProtoField`s, so the decoded values can be used
in display filters and exported with `tshark -T fields -e <field>` (or `-T json`):

| Dissector | Fields |
|---|---|
| `MouldKing.lua` | `mouldking.platform`, `.manufacturer`, `.cmd`, `.id`, `.data`, `.datagram`, `.payload` |
| `PowerBox.lua` | `powerbox.platform`, `.manufacturer`, `.cmd`, `.id`, `.data`, `.datagram`, `.payload` |
| `CaDA_RaceCar_PC.lua` | `cada.platform`, `.id`, `.cmd`, `.device_addr`, `.app_addr`, `.random`, `.channel1` .. `.channel3`, `.datagram`, `.payload` |
| `CaDA_RaceCar_HS.lua` | `cada_hs.platform`, `.cmd`, `.id1`, `.id2`, `.device_id`, `.app_id`, `.throttle`, `.steering`, `.lights`, `.offset`, `.seq`, `.datagram`, `.payload` |

Example: `tshark -r capture.pcap -Y "cada_hs.throttle < -50" -T fields -e cada_hs.throttle -e cada_hs.seq`.
The visible packet tree is unchanged: fields without a line of their own are hidden items.

## Tests

    lua5.4 tests/test_ble_tools.lua                       # pure Lua unit test of BLE_Tools.lua
    TSHARK=/path/to/tshark bash tests/run_tshark_tests.sh # runs the dissectors in tshark
    COMPARE_MAIN=1 TSHARK=... bash tests/run_tshark_tests.sh # also compares Info and packet tree with branch main

The tshark test generates identical packets as DLT 272, 256 and 251 captures (`tests/make_pcaps.py`)
and checks that the Info column is the same for all of them. See `tests/README.md`.

### Real captures in `tests/captures`

* `real_android.pcapng` (46 frames) and `real_ios.pcapng` (62 frames): a few real BrickController2 telegrams per
  device family, command and platform (MouldKing MK2.0 .. MK8.0, MK3.8, MK4.0/5.0, MK6.0, JIE-STAR 4CH[1..3] / 8CH,
  PowerBox, CaDA on Android). Only the app's own frames were kept (no foreign devices, no scan requests/responses);
  the link layer bytes are unchanged. The pcapng files are clean (no comments or system/interface information,
  synthetic timestamps). The iOS file comes from an nRF52840 sniffer capture of an iOS phone. The Android file was
  rebuilt from a Wireshark JSON export of captures of several devices: the advertising packets are real, but the
  pseudo header (channel, RSSI) is synthetic and the CRC is zeroed.
* `real_android.info` / `real_ios.info`: golden files with the expected Info column per frame; the tests compare
  them with the decoded output.
* `bleadvert_xn297l_dlt256.pcapng`: capture of the XN297L sniffer (MK4.0/5.0 Connect telegrams).
