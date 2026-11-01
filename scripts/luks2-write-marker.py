#!/usr/bin/env python3
"""Write a plaintext marker into a LUKS2 volume's payload, encrypted.

`check-luks2-image.sh` needs a sector the driver can be asked to decrypt, and
the obvious way — open the volume and write to it — needs device-mapper and
root.  This does the one AES-XTS pass instead, with the master key
`cryptsetup luksDump --dump-master-key` printed, so the plaintext the probe
asserts on is a value neither this tree nor the driver chose.

Arguments: <image> <master-key-hex> <marker>

Exit status is 0 when the marker is on the medium, non-zero with a reason on
stderr otherwise.
"""

import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_metadata(image: bytes) -> dict:
    """The JSON metadata block, which starts right after the binary header."""
    start = image.find(b'{"keyslots"')
    if start < 0:
        raise SystemExit("no LUKS2 JSON metadata in the image")

    depth = 0
    for end in range(start, len(image)):
        byte = image[end:end + 1]
        if byte == b"{":
            depth += 1
        elif byte == b"}":
            depth -= 1
            if depth == 0:
                return json.loads(image[start:end + 1].decode())
    raise SystemExit("the LUKS2 JSON metadata is not terminated")


def payload_offset(meta: dict) -> int:
    """Where the payload starts, in bytes."""
    return int(meta["segments"]["0"]["offset"])


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    image_path, key_hex, marker = argv[1], argv[2], argv[3]
    key = bytes.fromhex(key_hex.replace(" ", ""))
    if len(key) != 64:
        print(f"the master key is {len(key)} bytes, expected 64", file=sys.stderr)
        return 1

    with open(image_path, "rb") as handle:
        image = bytearray(handle.read())
    offset = payload_offset(load_metadata(bytes(image)))

    # The payload's first 512-byte data unit, tweaked by its index within the
    # payload — which is 0, because this is the payload's own first unit.
    plain = bytearray(512)
    marker_bytes = marker.encode()
    if len(marker_bytes) > 512:
        print("the marker does not fit in one sector", file=sys.stderr)
        return 1
    plain[:len(marker_bytes)] = marker_bytes

    tweak = bytearray(16)
    tweak[0:8] = struct.pack("<Q", 0)
    cipher = Cipher(algorithms.AES(key), modes.XTS(bytes(tweak)))
    ciphertext = cipher.encryptor().update(bytes(plain))

    image[offset:offset + 512] = ciphertext
    with open(image_path, "wb") as handle:
        handle.write(image)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
