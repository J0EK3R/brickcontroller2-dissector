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
| `MouldKing.lua` | `VARIANTS` table (Android / iOS / JieStar identifiers) and `COMMANDS` table (command byte -> name) |
| `PowerBox.lua` | `VARIANTS` table (Android / Windows / iOS) |
| `CaDA_RaceCar_PC.lua`, `CaDA_RaceCar_HS.lua` | device response plus `VARIANTS` table (Android / iOS) |

Adding a device:

* **new MouldKing command**: add one row to `COMMANDS` in `MouldKing.lua` (`length`, `manufacturer`,
  `name`, `kind = "connect"` or `"command"`, a sample datagram as comment);
* **new platform / app**: add one row to `VARIANTS` (`advLen`, identifying bytes in `pattern`,
  where the payload starts, decryption parameters).

The code style is described by `.editorconfig` (4 spaces, no tabs). Lua 5.3 or newer is required, the
native bit operators are used (there is no dependency on the `bit` library).

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
