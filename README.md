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

## Tests

    lua5.4 tests/test_ble_tools.lua                       # pure Lua unit test of BLE_Tools.lua
    TSHARK=/path/to/tshark bash tests/run_tshark_tests.sh # runs the dissectors in tshark

The tshark test generates identical packets as DLT 272, 256 and 251 captures (`tests/make_pcaps.py`)
and checks that the Info column is the same for all of them. See `tests/README.md`.
