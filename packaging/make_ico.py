#!/usr/bin/env python3
"""Pack packaging/qpwnagotchi-<size>.png into packaging/qpwnagotchi.ico.

Pure stdlib: ICO files may embed PNG images directly (Vista+).
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SIZES = (16, 24, 32, 48, 64, 128, 256)


def main() -> None:
    imgs = []
    for s in SIZES:
        with open(os.path.join(HERE, f"qpwnagotchi-{s}.png"), "rb") as fh:
            imgs.append((s, fh.read()))
    out = bytearray(struct.pack("<HHH", 0, 1, len(imgs)))
    offset = 6 + 16 * len(imgs)
    for s, data in imgs:
        out += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in imgs:
        out += data
    with open(os.path.join(HERE, "qpwnagotchi.ico"), "wb") as fh:
        fh.write(out)


if __name__ == "__main__":
    main()
