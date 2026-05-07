#!/usr/bin/env python3
"""
Live interop validator: pinned announce wire bytes vs current upstream RNS.

For every vector in `<spec_root>/test-vectors/announces.json`, push the
`expected.wire_bytes_hex` through `RNS.Identity.validate_announce` and
assert:

    1. The validator returns True (signature + structure accepted).
    2. The validator's `destination_hash` matches the vector's expected.
    3. `RNS.Identity.recall(dest_hash).get_public_key()` matches the
       public key derived from the matching identity vector's
       `private_key_hex`.

If anything mismatches, exit nonzero — CI fails the `interop` job and
we know upstream RNS has drifted from the pinned snapshot (or our
snapshot is stale).

Usage:
    pip install rns
    python tools/interop/validate_announce_vectors.py [<spec_root>]

Default spec_root is `../reticulum-specifications` (the sibling-checkout
layout used during local dev). CI passes its checkout path explicitly.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import RNS


def init_rns() -> None:
    """Bring up a minimal RNS instance with no transport / interfaces."""
    cfg_dir = tempfile.mkdtemp(prefix="rns-validator-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def load_identity_pubs(identities_path: str) -> dict[str, str]:
    """Map identity label → expected public_key_hex (X25519 || Ed25519, 64 B)."""
    with open(identities_path, encoding="utf-8") as f:
        data = json.load(f)
    out: dict[str, str] = {}
    for vec in data["vectors"]:
        out[vec["label"]] = vec["expected"]["public_key_hex"]
    return out


def validate_one(vec: dict, identity_pubs: dict[str, str]) -> tuple[bool, str]:
    """Validate one announce vector. Returns (passed, message)."""
    label = vec["label"]
    wire_hex = vec["expected"]["wire_bytes_hex"]
    expected_dest_hex = vec["expected"]["destination_hash_hex"]
    identity_label = vec["inputs"]["identity_label"]

    raw = bytes.fromhex(wire_hex)

    # Reconstruct an inbound RNS.Packet from raw bytes per
    # python_peer.cmd_validate_announce — this is the path Reticulum
    # uses internally on receive.
    pkt = RNS.Packet(None, raw)
    pkt.raw = raw
    pkt.packed = True
    if not pkt.unpack():
        return False, f"{label}: Packet.unpack returned False"

    if not bool(RNS.Identity.validate_announce(pkt)):
        return False, f"{label}: validate_announce returned False"

    actual_dest_hex = pkt.destination_hash.hex()
    if actual_dest_hex != expected_dest_hex:
        return False, (
            f"{label}: dest_hash mismatch — got {actual_dest_hex}, "
            f"expected {expected_dest_hex}"
        )

    cached = RNS.Identity.recall(pkt.destination_hash)
    if cached is None:
        return False, f"{label}: Identity.recall returned None"
    actual_pub_hex = cached.get_public_key().hex()
    expected_pub_hex = identity_pubs.get(identity_label)
    if expected_pub_hex is None:
        return False, (
            f"{label}: identity label {identity_label!r} not found in "
            f"identities.json"
        )
    if actual_pub_hex != expected_pub_hex:
        return False, (
            f"{label}: pub_hex mismatch for identity {identity_label} — "
            f"got {actual_pub_hex}, expected {expected_pub_hex}"
        )
    return True, f"{label}: OK"


def main() -> int:
    spec_root = sys.argv[1] if len(sys.argv) > 1 else "../reticulum-specifications"
    vectors_path = os.path.join(spec_root, "test-vectors", "announces.json")
    identities_path = os.path.join(spec_root, "test-vectors", "identities.json")

    if not os.path.exists(vectors_path):
        print(f"FATAL: announces.json not found at {vectors_path}", file=sys.stderr)
        return 2
    if not os.path.exists(identities_path):
        print(f"FATAL: identities.json not found at {identities_path}", file=sys.stderr)
        return 2

    init_rns()
    print(f"validating against RNS {RNS.__version__}")

    identity_pubs = load_identity_pubs(identities_path)

    with open(vectors_path, encoding="utf-8") as f:
        data = json.load(f)
    vectors = data["vectors"]

    passes = 0
    failures: list[str] = []
    for vec in vectors:
        ok, msg = validate_one(vec, identity_pubs)
        print(("  PASS  " if ok else "  FAIL  ") + msg)
        if ok:
            passes += 1
        else:
            failures.append(msg)

    print()
    print(f"summary: {passes}/{len(vectors)} announce vectors validated")
    if failures:
        print(f"failures: {len(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
