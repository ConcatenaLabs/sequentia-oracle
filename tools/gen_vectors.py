#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Write vectors/attestations.json: the golden vectors of both formats.

    python3 tools/gen_vectors.py > vectors/attestations.json

Every value is derived from fixed inputs, and signatures use the all-zero
auxiliary randomness, so the output is the same on every run and in every
language. The keys are test keys whose secrets are printed in the file; they
must never sign anything real.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from sequentia_oracle import attestation as A    # noqa: E402


def h(s):
    return hashlib.sha256(s.encode()).digest()


def main():
    keys = {name: h(f"sequentia-oracle/vector-key/{name}") for name in ("A", "B")}
    gold = h("vector asset GOLD").hex()     # display order, as an RPC prints it
    usdx = h("vector asset USDX").hex()
    silver = h("vector asset SILVR").hex()

    def asset(display):
        return A.asset_from_display(display)

    cases = [
        # The attestation every proof uses: GOLD in USDX, 3,000 USDX atoms per
        # GOLD atom at precision 5 (the Pignus testnet's price scale of 1e5).
        ("gold_usdx", "A", "GOLD/USDX", asset(gold), asset(usdx), 300_000_000, 5,
         1_790_000_000, A.NO_BEACON),
        # The same oracle and time, another pair: what "wrong pair" presents.
        ("silver_usdx", "A", "SILVR/USDX", asset(silver), asset(usdx), 3_500_000, 5,
         1_790_000_000, A.NO_BEACON),
        # Another oracle, the same pair, price and time: what "wrong key" presents.
        ("gold_usdx_key_b", "B", "GOLD/USDX", asset(gold), asset(usdx), 300_000_000, 5,
         1_790_000_000, A.NO_BEACON),
        # Native bitcoin in US dollars, both units rather than assets: one
        # satoshi at 60,000 USD a bitcoin is 60,000 USD atoms of 1e-8 USD.
        ("btc_usd", "A", "BTC/USD", A.unit_id("BTC"), A.unit_id("USD"), 60_000, 0,
         1_790_000_060, A.NO_BEACON),
        # A non-zero beacon, so every reader is proven to carry the field.
        ("gold_usdx_beacon", "A", "GOLD/USDX", asset(gold), asset(usdx), 300_000_000, 5,
         1_790_000_000, h("vector beacon")),
        # The largest values each field allows.
        ("limits", "A", "GOLD/USDX", asset(gold), asset(usdx), (1 << 63) - 1,
         A.MAX_PRECISION, (1 << 32) - 1, bytes([0xff]) * 32),
    ]
    v2 = []
    for name, k, market, base, quote, price, precision, t, beacon in cases:
        att = A.AttestationV2(A.xonly_pubkey(keys[k]), base, quote, price,
                              precision, t, beacon).sign(keys[k])
        assert att.verify()
        v2.append({"name": name, "signer": k, "market": market,
                   **att.fields(), "message": att.message().hex(),
                   "digest": att.digest().hex(), "signature": att.signature.hex()})

    # Format 1 for the first case: same oracle, market, time and price.
    g = cases[0]
    d1 = A.v1_sign(keys["A"], g[2], g[7], g[5], 10 ** g[6])
    v1 = [{"name": "gold_usdx", "signer": "A", **d1,
           "message": A.v1_message(bytes.fromhex(d1["feed_id"]), g[7], g[5]).hex()}]

    good = bytes.fromhex(v2[0]["message"])

    def edit(off, val):
        m = bytearray(good)
        m[off:off + len(val)] = val
        return bytes(m).hex()

    refusals = [
        {"name": "short", "message": good[:-1].hex(), "reason": "142 bytes"},
        {"name": "long", "message": (good + b"\0").hex(), "reason": "142 bytes"},
        {"name": "version_1", "message": edit(0, b"\x01"), "reason": "version"},
        {"name": "version_3", "message": edit(0, b"\x03"), "reason": "version"},
        {"name": "price_zero", "message": edit(97, bytes(8)), "reason": "price"},
        {"name": "price_2_63", "message": edit(97, (1 << 63).to_bytes(8, "little")),
         "reason": "price"},
        {"name": "precision_19", "message": edit(105, b"\x13"), "reason": "precision"},
        {"name": "base_is_quote", "message": edit(33, good[65:97]), "reason": "same"},
        {"name": "format_1_message", "message": v1[0]["message"], "reason": "142 bytes"},
    ]

    out = {
        "about": "Golden vectors for sequentia-oracle attestation formats 1 and 2 "
                 "(doc/format.md). Regenerate with tools/gen_vectors.py; never "
                 "edit by hand. Test keys only.",
        "tag": A.TAG,
        "tag_hash": hashlib.sha256(A.TAG.encode()).hexdigest(),
        "message_len": A.MESSAGE_LEN,
        "layout": [{"field": n, "offset": o, "length": ln} for n, o, ln in A.LAYOUT],
        "units": {u: A.unit_id(u).hex() for u in A.UNITS},
        "keys": {k: {"secret": s.hex(), "key": A.xonly_pubkey(s).hex()}
                 for k, s in keys.items()},
        "assets_display": {"GOLD": gold, "USDX": usdx, "SILVR": silver},
        "v2": v2,
        "v1": v1,
        "v2_refusals": refusals,
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
