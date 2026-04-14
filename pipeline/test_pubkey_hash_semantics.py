#!/usr/bin/env python3
"""
Regression tests for QSB pubkey hash semantics:
- The puzzle/search path must use RIPEMD160(compressed_pubkey), not HASH160.
"""

from secp256k1 import (
    G, point_mul, compress_pubkey, ripemd160, hash160, ripemd160_compressed_pubkey
)


def test_compressed_pubkey_shape():
    pub = compress_pubkey(point_mul(1, G))
    assert len(pub) == 33, f"compressed pubkey length mismatch: {len(pub)}"
    assert pub[0] in (0x02, 0x03), f"invalid prefix: 0x{pub[0]:02x}"


def test_direct_ripemd160_semantics():
    pub = compress_pubkey(point_mul(0x12345, G))
    direct = ripemd160_compressed_pubkey(pub)
    legacy = hash160(pub)
    assert direct == ripemd160(pub), "helper must compute RIPEMD160(pubkey33)"
    assert direct != legacy, "regression: direct RIPEMD160 must not be HASH160"


if __name__ == "__main__":
    test_compressed_pubkey_shape()
    test_direct_ripemd160_semantics()
    print("OK: pubkey hash semantics tests passed")
