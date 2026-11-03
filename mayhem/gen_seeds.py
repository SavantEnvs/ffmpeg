#!/usr/bin/env python3
"""Regenerate the seeds under mayhem/<target>/testsuite/ for the four targets that random bytes cannot enter.

The upstream harnesses (tools/target_{bsf,dec,enc}_fuzzer.c) read a 1024-byte parameter block from the END of
the input and then need well-formed content before the library does any real work:
  - target_bsf_h264_metadata_fuzzer: Annex-B NAL units (start codes) split by the FUZZ_TAG
  - target_dec_vorbis_fuzzer:        Xiph-laced Vorbis headers as extradata + Vorbis audio packets
  - target_enc_mjpeg/mpeg4_fuzzer:   avcodec_open2() only succeeds for sane width/time_base/pix_fmt values
Usage: gen_seeds.py <ogg-file-written-by-ffmpeg-vorbis-encoder>   (run from the repo root)
"""
import struct
import sys
from pathlib import Path

FUZZ_TAG = struct.pack("<Q", 0x4741542D5A5A5546)
ROOT = Path(__file__).resolve().parent


class Bits:
    def __init__(self):
        self.bits = []

    def u(self, n, v):
        self.bits += [(v >> i) & 1 for i in range(n - 1, -1, -1)]

    def ue(self, v):
        v += 1
        n = v.bit_length()
        self.u(n - 1, 0)
        self.u(n, v)

    def se(self, v):
        self.ue(2 * v - 1 if v > 0 else -2 * v)

    def rbsp(self):
        b = self.bits + [1]
        b += [0] * (-len(b) % 8)
        return bytes(int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def nal(header, payload):
    out = bytearray()
    zeros = 0
    for byte in payload:
        if zeros >= 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return b"\x00\x00\x00\x01" + bytes([header]) + bytes(out)


def h264_stream(slice_bytes):
    sps = Bits()
    sps.u(8, 66); sps.u(8, 0xC0); sps.u(8, 10)
    sps.ue(0); sps.ue(0); sps.ue(2); sps.ue(1); sps.u(1, 0)
    sps.ue(3); sps.ue(3); sps.u(1, 1); sps.u(1, 1); sps.u(1, 0); sps.u(1, 0)
    pps = Bits()
    pps.ue(0); pps.ue(0); pps.u(1, 0); pps.u(1, 0); pps.ue(0); pps.ue(0); pps.ue(0)
    pps.u(1, 0); pps.u(2, 0); pps.se(0); pps.se(0); pps.se(0); pps.u(1, 1); pps.u(1, 0); pps.u(1, 0)
    idr = Bits()
    idr.ue(0); idr.ue(7); idr.ue(0); idr.u(4, 0); idr.ue(0); idr.u(1, 0); idr.u(1, 0)
    idr.se(0); idr.ue(1)
    head = idr.bits + [0] * (-len(idr.bits) % 8)
    head_bytes = bytes(int("".join(map(str, head[i:i + 8])), 2) for i in range(0, len(head), 8))
    aud = nal(0x09, b"\xf0")
    return (aud + nal(0x67, sps.rbsp()) + nal(0x68, pps.rbsp()) + nal(0x65, head_bytes + slice_bytes))


def put(target, name, data):
    d = ROOT / target / "testsuite"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def pattern(n, seed):
    x = seed
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def header_block(fields):
    return fields.ljust(1024, b"\x00")


def bsf_seeds():
    t = "target_bsf_h264_metadata_fuzzer"
    pad = header_block(b"")
    p1 = h264_stream(pattern(40, 1))
    p2 = h264_stream(pattern(24, 2))
    put(t, "idr.bin", p1 + pad)
    put(t, "two_packets.bin", p1 + FUZZ_TAG + p2 + pad)
    flags = struct.pack("<I", 64) + struct.pack("<I", 64) + struct.pack("<Q", 0) + struct.pack("<I", 0)
    flags += b"\x00" + struct.pack("<I", 0) + struct.pack("<I", 0)
    flags += struct.pack("<I", 0) * 3 + struct.pack("<Q", 0b1110) + struct.pack("<Q", 2**64 - 1) + b"\x20\x01"
    put(t, "idr_aud_option.bin", p1 + FUZZ_TAG + p2 + header_block(flags))


def enc_header(width, height, gop, max_b, pix_fmt_idx, flags=0):
    h = struct.pack("<II", width, height) + struct.pack("<Q", 400000)
    h += struct.pack("<II", gop, max_b) + struct.pack("<II", 1, 25) + struct.pack("<II", 25, 1)
    h += bytes([flags]) + struct.pack("<Q", 0) + bytes([pix_fmt_idx])
    return header_block(h)


def enc_seeds():
    t = "target_enc_mjpeg_fuzzer"
    for idx in range(6):
        for flags in (0, 2):
            put(t, f"w32_pix{idx}_f{flags}.bin", pattern(2200, 10 + idx) + enc_header(32, 32, 12, 0, idx, flags))
    t = "target_enc_mpeg4_fuzzer"
    for max_b in (0, 2):
        for flags in (0, 2):
            put(t, f"w32_b{max_b}_f{flags}.bin", pattern(2200, 20 + max_b) + enc_header(32, 32, 12, max_b, 0, flags))


def vorbis_seeds(ogg):
    data = Path(ogg).read_bytes()
    packets, cur, pos = [], b"", 0
    while pos < len(data):
        assert data[pos:pos + 4] == b"OggS"
        nseg = data[pos + 26]
        lacing = data[pos + 27:pos + 27 + nseg]
        pos += 27 + nseg
        for lace in lacing:
            cur += data[pos:pos + lace]
            pos += lace
            if lace < 255:
                packets.append(cur)
                cur = b""
    ident, comment, setup = packets[:3]

    def lace(n):
        return b"\xff" * (n // 255) + bytes([n % 255])

    extradata = b"\x02" + lace(len(ident)) + lace(len(comment)) + ident + comment + setup
    rate = struct.unpack("<I", ident[12:16])[0]
    chans = ident[11]
    blocksize = ident[28]
    t = "target_dec_vorbis_fuzzer"
    for n in (4, 12):
        audio = FUZZ_TAG.join(packets[3:3 + n])
        h = struct.pack("<II", 0, 0) + struct.pack("<Q", 0) + struct.pack("<I", 0)
        h += b"\x00" + struct.pack("<I", len(extradata)) + struct.pack("<I", rate)
        h += struct.pack("<I", chans) + struct.pack("<I", 0) + struct.pack("<I", 0)
        h = header_block(h)
        put(t, f"stereo_{n}pkt.bin", audio + extradata + h)
    assert blocksize


if __name__ == "__main__":
    bsf_seeds()
    enc_seeds()
    vorbis_seeds(sys.argv[1])
