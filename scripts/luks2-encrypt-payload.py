#!/usr/bin/env python3
"""Encrypt a filesystem image into a LUKS2 volume's payload.

`check-luks2-zone.sh` has a zone image the kernel's own builder made and a
volume `cryptsetup` wrote, and needs the first inside the second.  Opening the
volume needs device-mapper and root; this does the AES-XTS pass instead, with
the master key `luksDump --dump-master-key` printed.

Arguments: <volume> <master-key-hex> <filesystem-image>

The image is encrypted a 512-byte data unit at a time, tweaked by its index
*within the payload*, which is what the format says and what `luks2_open`
counts from.  Exit status is 0 when the payload holds the encrypted image.
"""

import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

UNIT = 512


def load_metadata(volume: bytes) -> dict:
    start = volume.find(b'{"keyslots"')
    if start < 0:
        raise SystemExit("no LUKS2 JSON metadata in the volume")
    depth = 0
    for end in range(start, len(volume)):
        byte = volume[end:end + 1]
        if byte == b"{":
            depth += 1
        elif byte == b"}":
            depth -= 1
            if depth == 0:
                return json.loads(volume[start:end + 1].decode())
    raise SystemExit("the LUKS2 JSON metadata is not terminated")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    volume_path, key_hex, image_path = argv[1], argv[2], argv[3]
    key = bytes.fromhex(key_hex.replace(" ", ""))
    if len(key) != 64:
        print(f"the master key is {len(key)} bytes, expected 64", file=sys.stderr)
        return 1

    with open(volume_path, "rb") as handle:
        volume = bytearray(handle.read())
    payload = int(load_metadata(bytes(volume))["segments"]["0"]["offset"])

    with open(image_path, "rb") as handle:
        image = bytearray(handle.read())

    # A string only this volume carries.  Without it the check passes on a
    # volume whose payload was never encrypted at all — measured: writing the
    # plaintext instead of the ciphertext left the gate green, because `cat`
    # read the in-memory demo volume's file of the same name.  Replacing a
    # file's text with a value no other copy has is what makes the read
    # attributable to *this* payload rather than to a fallback that happens to
    # be mounted at the same path.
    original = b"Shared data volume used by the host-side regression tests."
    replacement = b"PROTOFIRE-ENCRYPTED-PAYLOAD-PROOF".ljust(len(original), b" ")
    if original not in image:
        print("the data image does not carry the file this check reads",
              file=sys.stderr)
        return 1
    image = bytearray(bytes(image).replace(original, replacement))

    available = len(volume) - payload
    if len(image) > available:
        print(
            f"the image is {len(image)} bytes and the payload has {available}",
            file=sys.stderr,
        )
        return 1

    # Whole units only: XTS encrypts a block at a time, so a partial tail is
    # padded to the unit — which the filesystem never reads, because its own
    # length says where it ends.
    padded = image + b"\0" * (-len(image) % UNIT)
    for index in range((len(padded) + UNIT - 1) // UNIT):
        unit = padded[index * UNIT:(index + 1) * UNIT]
        tweak = bytearray(16)
        tweak[0:8] = struct.pack("<Q", index)
        cipher = Cipher(algorithms.AES(key), modes.XTS(bytes(tweak)))
        ciphertext = cipher.encryptor().update(unit)
        volume[payload + index * UNIT:payload + (index + 1) * UNIT] = ciphertext

    with open(volume_path, "wb") as handle:
        handle.write(volume)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
