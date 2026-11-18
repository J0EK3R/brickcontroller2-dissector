#!/usr/bin/env python3
"""
make_pcaps.py - generate test captures for the Lua post-dissectors.

Every dissector variant (MouldKing Android/iOS, CaDA PC/HS Android, PowerBox
Android/Windows/iOS) is written as ONE identical BLE advertising packet in three
capture formats, so that tests can check that the dissectors do not depend on the
capture link type:

    DLT 272  LINKTYPE_NORDIC_BLE                   17 byte Nordic nRF Sniffer header + LL packet
    DLT 256  LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR    10 byte pseudo header + LL packet
    DLT 251  LINKTYPE_BLUETOOTH_LE_LL              LL packet only

LL packet = access address(4) + PDU header(2) + AdvA(6) + advertising data + CRC(3).

The payloads are real: they are encrypted with a Python port of Crypt_Tools.lua
(GetRfPayload), so that the identifier bytes the dissectors look for appear
naturally and the dissectors decrypt a known command.

Usage: make_pcaps.py <output-dir>
Writes <variant>_dlt<N>.pcap and <variant>.info (the expected Info substring).
Standard library only.
"""

import os
import struct
import sys

ADV_AA = 0x8E89BED6                 # access address of advertising channel packets
ADV_ADDR = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])   # AdvA used in all packets
CRC = bytes([0xAB, 0xCD, 0xEF])     # dummy CRC (not checked by the dissectors)


# --------------------------------------------------------------------------
# Python port of the encrypt side of Crypt_Tools.lua
# --------------------------------------------------------------------------
def invert8(v):
    """Reverse the bit order of a byte."""
    return int(format(v & 0xFF, "08b")[::-1], 2)


def invert16(v):
    """Reverse the bit order of a 16 bit value."""
    return int(format(v & 0xFFFF, "016b")[::-1], 2)


def crc16(seed, data):
    """CheckCRC16 of Crypt_Tools.lua: CRC over the reversed seed and the bit-inverted data."""
    result = 0xFFFF
    for b in list(reversed(seed)) + [invert8(x) for x in data]:
        # Lua: seed bytes are used as they are, data bytes are bit-inverted first
        result ^= b << 8
        for _ in range(8):
            result = ((result << 1) & 0xFFFF) if not result & 0x8000 else (((result << 1) ^ 0x1021) & 0xFFFF)
    return (invert16(result) ^ 0xFFFF) & 0xFFFF


def whitening_encode(buf, start, length, ctx_value):
    """In-place whitening of buf[start:start+length] with the 7 bit LFSR seeded by ctx_value."""
    ctx = [1] + [(ctx_value >> s) & 1 for s in (5, 4, 3, 2, 1, 0)]
    for i in range(start, start + length):
        out = 0
        for bit_index in range(8):
            v3, v6 = ctx[3], ctx[6]                      # WhiteningOutput
            ctx[3], ctx[2], ctx[1], ctx[0] = ctx[2], ctx[1], ctx[0], ctx[6]
            ctx[6], ctx[5] = ctx[5], ctx[4]
            ctx[4] = v3 ^ v6
            out |= (ctx[0] ^ ((buf[i] >> bit_index) & 1)) << bit_index
        buf[i] = out


def encrypt(seed, header, data, header_offset, ctx1, ctx2):
    """GetRfPayload of Crypt_Tools.lua: returns the RF payload bytes."""
    seed_off = header_offset + len(header)
    data_off = seed_off + len(seed)
    crc_off = data_off + len(data)
    buf = [0] * (crc_off + 2)
    buf[header_offset:seed_off] = header
    buf[seed_off:data_off] = list(reversed(seed))
    for i in range(header_offset, data_off):             # header + seed are bit-inverted
        buf[i] = invert8(buf[i])
    buf[data_off:crc_off] = data
    checksum = crc16(seed, data)
    buf[crc_off], buf[crc_off + 1] = checksum >> 8, checksum & 0xFF
    whitening_encode(buf, seed_off, len(seed) + len(data) + 2, ctx1)
    whitening_encode(buf, 0, len(buf), ctx2)
    return bytes(buf[header_offset:])


def derive_header(ident, header_offset, ctx2):
    """Recover the 3 plain header bytes from the first 3 identifier bytes the dissector checks."""
    buf = [0] * header_offset + list(ident[:3])
    whitening_encode(buf, 0, len(buf), ctx2)             # whitening is its own inverse
    return [invert8(b) for b in buf[header_offset:]]


def make_payload(seed, ident, data, header_offset, ctx1, ctx2):
    """Encrypt data so that the RF payload starts with the dissector identifier bytes."""
    header = derive_header(ident, header_offset, ctx2)
    if len(header) < 3:
        # The dissector only checks the first byte(s) (PowerBox iOS): take the rest of the
        # header from the MouldKing family, which shares the header format.
        header += derive_header([0x6D, 0xB6, 0x43], 15, ctx2)[len(header):]
    payload = encrypt(seed, header, data, header_offset, ctx1, ctx2)
    # Self check of the port: the encrypted prefix must equal the identifier the dissector expects.
    assert payload[:len(ident)] == bytes(ident), (payload.hex(), bytes(ident).hex())
    return payload


# --------------------------------------------------------------------------
# Advertising data of each dissector variant
# --------------------------------------------------------------------------
SEED_MK = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5]
FLAGS = bytes([0x02, 0x01, 0x06])                        # "Flags" AD structure


def ad(ad_type, body):
    """One AD structure: length byte, type, body."""
    return bytes([len(body) + 1, ad_type]) + bytes(body)


def mk_android():
    """MouldKing Android: command 0x66 (8 byte payload, fill bytes 13 14 ..), advLen 31."""
    payload = make_payload(SEED_MK, [0x6D, 0xB6, 0x43, 0xCF, 0x7E, 0x8F, 0x47, 0x11],
                           [0x66, 0x7B, 0xA7, 0x80, 0x80, 0x80, 0x80, 0x99], 15, 0x3F, 0x25)
    fill = bytes(range(0x13, 0x13 + 28 - 4 - len(payload)))
    return FLAGS + ad(0xFF, bytes([0xF0, 0xFF]) + payload + fill)


def mk_ios():
    """MouldKing iOS: connect command 0xaa, advLen 23."""
    payload = make_payload(SEED_MK, [0xF9, 0x08, 0x49, 0x22, 0x47, 0xBA, 0xC4, 0xBC],
                           [0xAA, 0x7B, 0xA7, 0x00, 0x00, 0x00, 0x00, 0x55], 13, 0x3F, 0x25)
    return FLAGS + ad(0x03, payload)                     # +4 type, +5.. payload


def powerbox_payload(first_ident, header_offset):
    """PowerBox command 0x40 payload (8 byte data)."""
    return make_payload(SEED_MK, first_ident, [0x40, 0x7B, 0xA7, 0x01, 0x02, 0x03, 0x04, 0x05],
                        header_offset, 0x3F, 0x25)


def powerbox_android():
    """PowerBox Android, advLen 25."""
    p = powerbox_payload([0x6D, 0xB6, 0x43, 0xCF, 0x7E, 0x8F, 0x47], 15)
    return FLAGS + ad(0xFF, bytes([0x00, 0xFF]) + p)


def powerbox_windows():
    """PowerBox Windows: NO Flags AD, manufacturer AD (length 0x1d) first, advLen 30."""
    p = powerbox_payload([0x6D, 0xB6, 0x43, 0xCF], 15)
    return bytes([0x1D, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00]) + p + bytes(range(0x01, 6))


def powerbox_ios():
    """PowerBox iOS: Flags + TX power AD + 16-bit UUID list AD (length 0x13), advLen 26."""
    p = powerbox_payload([0xC8], 16)
    return FLAGS + bytes([0x02, 0x0A, 0x00]) + ad(0x03, p)


def cada_pc_android():
    """CaDA PC Android: connect (0x75 0x10) payload, advLen 31."""
    p = make_payload([0x43, 0x41, 0x52], [0xEE, 0x1B, 0xC8, 0xAF, 0x9F, 0x3C],
                     [0x75, 0x10] + [0x00] * 14, 15, 0x3F, 0x26)
    return FLAGS + ad(0xFF, bytes([0x00, 0xC2]) + p)


def cada_hs_android():
    """CaDA HS Android: control frame (0xbb ...), advLen 23, footer cc b8 92 b0."""
    body = bytes([0x00, 0xC2,                             # company id
                  0xBB, 0x11, 0x11, 0xC9, 0xC1, 0x79, 0x29,   # cmd, header, device id, app id
                  0x80, 0x80, 0x00, 0x00, 0x05,           # throttle, steering, lights, offset, seq
                  0xCC, 0xB8, 0x92, 0xB0])                # footer
    return FLAGS + ad(0xFF, body)


# name -> (builder, expected advertising data length, expected Info substring)
VARIANTS = {
    "mk_android": (mk_android, 31, "Android - MouldKing - MK2.0/MK3.0/MK4.0D/MK8.0 Command - Cmd[66] ID[7b a7] 80 80 80 80"),
    # KNOWN PRE-EXISTING BUG (not part of task 020): MouldKing.lua reads 26 bytes of iOS payload
    # but only 18 exist, so the dissector raises "Range is out of bounds" for every iOS frame
    # (identically on branch main) and the Info column keeps the btle text. The test therefore
    # only checks that all link types and the original code behave identically.
    "mk_ios": (mk_ios, 23, "ADV_NONCONN_IND"),
    "powerbox_android": (powerbox_android, 25, "Android - PowerBox - Command Cmd[40] ID[7b a7] 01 02 03 04"),
    "powerbox_windows": (powerbox_windows, 30, "Windows - PowerBox - Command Cmd[40] ID[7b a7] 01 02 03 04"),
    "powerbox_ios": (powerbox_ios, 26, "iOS - PowerBox - Command Cmd[40]"),
    "cada_pc_android": (cada_pc_android, 31, "CaDA - Connect"),
    "cada_hs_android": (cada_hs_android, 23, "Android - CaDA HS - Control Seq="),
}


# --------------------------------------------------------------------------
# Packet and capture file builders
# --------------------------------------------------------------------------
def ll_packet(adv_data, access_address=ADV_AA, cut=0):
    """Build AA + PDU header (ADV_NONCONN_IND) + AdvA + AdvData + CRC; cut drops trailing bytes."""
    pdu = bytes([0x42, 6 + len(adv_data)]) + ADV_ADDR + adv_data
    return (struct.pack("<I", access_address) + pdu + CRC)[:len(adv_data) + 15 - cut]


def phdr_256(aa):
    """10 byte DLT 256 pseudo header (see ble_phdr.py of the xn297l-sniffer): ch 37, -50 dBm."""
    flags = 0x0001 | 0x0002 | 0x0010 | 0x0400 | 0x0800   # dewhitened, rssi, ref AA, CRC checked + ok
    return struct.pack("<BbbBIH", 0, -50, 0, 0, aa, flags)


def nordic_272(ll):
    """17 byte Nordic nRF Sniffer header (packet-nordic_ble.c, protocol version 3) + LL packet.

    board(1) payload_len(2) version(1)=3 counter(2) packet_id(1) (2 = advertising PDU, 6 = data PDU)   = 7 bytes
    then the event header: LL length(1) flags(1)=CRC ok channel(1)=37 rssi(1)
    event counter(2) timestamp(4)                                                      = 10 bytes
    """
    event = struct.pack("<BBBBHI", len(ll), 0x01, 37, 0x32, 0, 0)
    packet_id = 2 if ll[:4] == struct.pack("<I", ADV_AA) else 6   # 2 = advertising PDU, 6 = data PDU
    head = struct.pack("<BHBHB", 0, len(event) + len(ll), 3, 1, packet_id)
    assert len(head + event) == 17
    return head + event + ll


def write_pcap(path, linktype, packets):
    """Write a classic pcap file with the given link type."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)


def write_all(outdir, name, ll):
    """Write the same LL packet in the three capture formats."""
    aa = struct.unpack("<I", ll[:4])[0]
    write_pcap(os.path.join(outdir, name + "_dlt272.pcap"), 272, [nordic_272(ll)])
    write_pcap(os.path.join(outdir, name + "_dlt256.pcap"), 256, [phdr_256(aa) + ll])
    write_pcap(os.path.join(outdir, name + "_dlt251.pcap"), 251, [ll])


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, (build, adv_len, expected) in VARIANTS.items():
        adv = build()
        assert len(adv) == adv_len, (name, len(adv), adv_len)
        write_all(outdir, name, ll_packet(adv))
        with open(os.path.join(outdir, name + ".info"), "w") as f:
            f.write(expected + "\n")
    # Negative captures: must NOT be touched by any dissector.
    mk = mk_android()
    wrong = bytearray(mk)
    wrong[3 + 4 + 2] ^= 0xFF                              # corrupt the MouldKing identifier
    write_all(outdir, "neg_wrong_identifier", ll_packet(bytes(wrong)))
    write_all(outdir, "neg_data_pdu", ll_packet(mk, access_address=0x12345678))
    write_all(outdir, "neg_truncated", ll_packet(mk, cut=20))
    write_all(outdir, "neg_other_length", ll_packet(mk + b"\x00"))
    # A capture without any btle layer: Ethernet link type with junk.
    write_pcap(os.path.join(outdir, "neg_no_btle.pcap"), 1, [bytes(range(60))])


if __name__ == "__main__":
    main(sys.argv[1])
