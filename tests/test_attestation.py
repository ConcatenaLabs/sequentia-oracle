#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The formats: BIP340 itself, the golden vectors, and what each must refuse."""

import csv
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from sequentia_oracle import attestation as A    # noqa: E402

VECTORS = os.path.join(ROOT, "vectors", "attestations.json")


def load():
    with open(VECTORS) as f:
        return json.load(f)


class Bip340(unittest.TestCase):
    def test_specification_vectors(self):
        path = os.path.join(ROOT, "tests", "data", "bip340_test_vectors.csv")
        n = 0
        with open(path) as f:
            for r in csv.DictReader(f):
                pk = bytes.fromhex(r["public key"])
                msg = bytes.fromhex(r["message"])
                sig = bytes.fromhex(r["signature"])
                if r["secret key"]:
                    sec = bytes.fromhex(r["secret key"])
                    self.assertEqual(A.xonly_pubkey(sec), pk, r["index"])
                    self.assertEqual(A.schnorr_sign(sec, msg, bytes.fromhex(r["aux_rand"])),
                                     sig, r["index"])
                self.assertEqual(A.schnorr_verify(pk, msg, sig),
                                 r["verification result"] == "TRUE", r["index"])
                n += 1
        self.assertEqual(n, 15)

    def test_node_framework_agrees_on_any_length(self):
        """Format 1 signs 48 bytes. The node's own test framework signs any
        length for CHECKSIGFROMSTACK; where a node checkout is at hand, the two
        must produce the same bytes."""
        src = os.environ.get("SEQUENTIA_SRC")
        if not src:
            self.skipTest("SEQUENTIA_SRC not set")
        sys.path.insert(0, os.path.join(src, "test", "functional"))
        from test_framework import key as K           # noqa: PLC0415
        sec = bytes(31) + b"\x07"
        for n in (0, 1, 32, 48, 100):
            msg = bytes(range(n))
            self.assertEqual(A.schnorr_sign(sec, msg), K.sign_schnorr(sec, msg, aux=bytes(32)))

    def test_bad_secrets_are_refused(self):
        for bad in (b"", bytes(32), A.N.to_bytes(32, "big"), b"\x01" * 31):
            with self.assertRaises(ValueError):
                A.xonly_pubkey(bad)


class FormatTwo(unittest.TestCase):
    def setUp(self):
        self.v = load()

    def test_vectors_regenerate_byte_for_byte(self):
        out = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "gen_vectors.py")],
                             capture_output=True, check=True).stdout
        with open(VECTORS, "rb") as f:
            self.assertEqual(out, f.read())

    def test_constants(self):
        import hashlib
        self.assertEqual(self.v["tag"], "Sequentia/oracle/price")
        self.assertEqual(self.v["tag_hash"], hashlib.sha256(b"Sequentia/oracle/price").hexdigest())
        self.assertEqual(sum(f["length"] for f in self.v["layout"]), A.MESSAGE_LEN)
        off = 0
        for f in self.v["layout"]:
            self.assertEqual(f["offset"], off)
            off += f["length"]
        for u, h in self.v["units"].items():
            self.assertEqual(A.unit_id(u).hex(), h)
        with self.assertRaises(ValueError):
            A.unit_id("EUR")

    def test_every_vector(self):
        keys = self.v["keys"]
        for c in self.v["v2"]:
            sec = bytes.fromhex(keys[c["signer"]]["secret"])
            msg = bytes.fromhex(c["message"])
            att = A.AttestationV2.decode(msg, bytes.fromhex(c["signature"]))
            self.assertEqual(att.fields(), {k: c[k] for k in att.fields()}, c["name"])
            self.assertEqual(att.digest().hex(), c["digest"])
            self.assertEqual(A.tagged_hash(A.TAG, msg).hex(), c["digest"])
            self.assertTrue(att.verify(bytes.fromhex(keys[c["signer"]]["key"])), c["name"])
            fresh = A.AttestationV2.decode(msg).sign(sec)
            self.assertEqual(fresh.signature.hex(), c["signature"], c["name"])
            self.assertEqual(A.AttestationV2.from_dict(fresh.to_dict()), att)

    def test_every_byte_is_signed(self):
        c = self.v["v2"][4]                  # the one with a non-zero beacon
        msg = bytes.fromhex(c["message"])
        sig = bytes.fromhex(c["signature"])
        key = bytes.fromhex(c["key"])
        for i in range(len(msg)):
            m = bytearray(msg)
            m[i] ^= 0x01
            ok = A.schnorr_verify(key, A.tagged_hash(A.TAG, bytes(m)), sig)
            self.assertFalse(ok, f"byte {i} is not covered by the signature")

    def test_another_key_and_the_key_field(self):
        a, b = self.v["v2"][0], self.v["v2"][2]
        att = A.AttestationV2.decode(bytes.fromhex(a["message"]), bytes.fromhex(a["signature"]))
        self.assertFalse(att.verify(bytes.fromhex(b["key"])))
        # B's signature over A's fields: the key field still names A.
        forged = A.AttestationV2.decode(bytes.fromhex(a["message"]), bytes.fromhex(b["signature"]))
        self.assertFalse(forged.verify())
        with self.assertRaises(ValueError):
            A.AttestationV2.decode(bytes.fromhex(a["message"])).sign(
                bytes.fromhex(self.v["keys"]["B"]["secret"]))

    def test_refusals(self):
        for r in self.v["v2_refusals"]:
            with self.assertRaises(ValueError, msg=r["name"]) as cm:
                A.AttestationV2.decode(bytes.fromhex(r["message"]))
            self.assertIn(r["reason"], str(cm.exception), r["name"])

    def test_a_record_cannot_say_one_thing_and_sign_another(self):
        d = A.AttestationV2.decode(bytes.fromhex(self.v["v2"][0]["message"]),
                                   bytes.fromhex(self.v["v2"][0]["signature"])).to_dict()
        d["price"] += 1
        with self.assertRaises(ValueError):
            A.AttestationV2.from_dict(d)

    def test_display_order(self):
        gold = self.v["assets_display"]["GOLD"]
        self.assertEqual(self.v["v2"][0]["base"], bytes.fromhex(gold)[::-1].hex())
        self.assertEqual(A.asset_to_display(A.asset_from_display(gold)), gold)


class FormatOne(unittest.TestCase):
    def setUp(self):
        self.v = load()

    def test_vector(self):
        c = self.v["v1"][0]
        sec = bytes.fromhex(self.v["keys"]["A"]["secret"])
        key = bytes.fromhex(self.v["keys"]["A"]["key"])
        self.assertEqual(A.v1_feed_id("gold / usdx").hex(), c["feed_id"])
        self.assertEqual(A.v1_message(bytes.fromhex(c["feed_id"]), c["timestamp"], c["price"]).hex(),
                         c["message"])
        self.assertEqual(len(bytes.fromhex(c["message"])), A.V1_MESSAGE_LEN)
        d = A.v1_sign(sec, c["market"], c["timestamp"], c["price"], c["price_scale"])
        self.assertEqual(d["signature"], c["signature"])
        self.assertTrue(A.v1_verify(key, c))
        self.assertFalse(A.v1_verify(key, dict(c, price=c["price"] + 1)))
        self.assertFalse(A.v1_verify(key, dict(c, market="SILVR/USDX")))
        self.assertEqual(A.format_of(c), 1)
        self.assertEqual(A.format_of({"version": 2}), 2)

    def test_formats_do_not_cross(self):
        """The same oracle signs the same observation in both formats. Neither
        signature may verify as the other: a format-1 signature is over 48
        bytes and a format-2 one over a 32-byte tagged hash."""
        c1, c2 = self.v["v1"][0], self.v["v2"][0]
        key = bytes.fromhex(c2["key"])
        self.assertEqual((c1["timestamp"], c1["price"], c1["price_scale"]),
                         (c2["time"], c2["price"], 10 ** c2["precision"]))
        self.assertFalse(A.schnorr_verify(key, bytes.fromhex(c2["digest"]),
                                          bytes.fromhex(c1["signature"])))
        self.assertFalse(A.schnorr_verify(key, bytes.fromhex(c1["message"]),
                                          bytes.fromhex(c2["signature"])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
