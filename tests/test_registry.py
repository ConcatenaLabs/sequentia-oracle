#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The oracle's registry record: what the signer signs, what it refuses, and
the pinned example a registry checks the same signature against."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from sequentia_oracle import attestation as A     # noqa: E402
from sequentia_oracle import bond as B            # noqa: E402
from sequentia_oracle import registry as R        # noqa: E402

SIGNER = os.path.join(ROOT, "bin", "sequentia-oracle-signer")
EXAMPLE = os.path.join(ROOT, "vectors", "registry-record.json")
GOLD = "11" * 32
USDX = "22" * 32
BEACON = "33" * 32


def record(key, bond, **over):
    r = {"version": 2, "key": key.hex(),
         "feeds": [{"id": "GOLD/USDX", "description": "Gold in USDX", "decimals": 5}],
         "operator": {"name": "Example oracle", "domain": "oracle.example.com"},
         "endpoints": ["https://oracle.example.com/v2/log/raw"],
         "attestation_tag": A.TAG, "beacon_asset": BEACON,
         "bond": R.bond_terms(bond, "https://oracle.example.com/v2/bond/log") if bond else None,
         "revoked": False}
    if r["bond"] is None:
        del r["bond"]
    r.update(over)
    return r


class Signer(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="oracle-registry-")
        self.cfg = {"keyfile": os.path.join(self.dir, "oracle.key"), "formats": [2], "precision": 5,
                    "markets": ["GOLD/USDX"], "assets": {"GOLD": GOLD, "USDX": USDX},
                    "precisions": {"GOLD": 8, "USDX": 8}, "interval": 60,
                    "source": {"type": "static", "prices": {"GOLD": 3000, "USDX": 1}},
                    "bond": {"asset": USDX, "notice": 2592000}}
        self.cfg_path = os.path.join(self.dir, "signer.json")
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f)
        self.run_signer("--create-key", "--once")
        self.key = bytes.fromhex(self.run_signer("--print-pubkey").stdout.strip())
        self.bond = B.Bond(self.key, USDX, B.notice_sequence(2592000))

    def tearDown(self):
        subprocess.run(["rm", "-rf", "--", self.dir], check=True)

    def run_signer(self, *args, ok=True):
        p = subprocess.run([sys.executable, "-I", SIGNER, "--config", self.cfg_path] + list(args),
                           capture_output=True, text=True)
        if ok and p.returncode != 0:
            raise AssertionError(p.stderr)
        return p

    def sign(self, r):
        path = os.path.join(self.dir, "record.json")
        with open(path, "w") as f:
            json.dump(r, f)
        return self.run_signer("--sign-registry-record", path, ok=False)

    def test_signs_its_own_record_with_its_bond(self):
        r = record(self.key, self.bond)
        p = self.sign(r)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["record"], r)
        self.assertTrue(R.verify(out))
        self.assertEqual(out["record"]["bond"]["bonded"], self.bond.spk(B.BONDED))
        self.assertEqual(out["record"]["bond"]["noticed"], self.bond.spk(B.NOTICED))
        # The signature is over the record and the registry's tag only.
        self.assertTrue(A.schnorr_verify(self.key, A.tagged_hash(R.TAG, R.canonical(r)),
                                         bytes.fromhex(out["signature"])))
        self.assertFalse(A.schnorr_verify(self.key, A.tagged_hash(A.TAG, R.canonical(r)),
                                          bytes.fromhex(out["signature"])))

    def refused(self, r, words):
        p = self.sign(r)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("not signed", p.stderr)
        self.assertIn(words, p.stderr)
        self.assertEqual(p.stdout, "")

    def test_refuses_another_key(self):
        self.refused(record(A.xonly_pubkey(bytes([5]) * 32), self.bond), "a signer signs only its own record")

    def test_refuses_another_bond_asset(self):
        r = record(self.key, self.bond)
        r["bond"]["asset"] = GOLD
        self.refused(r, "bond.asset")

    def test_refuses_another_notice(self):
        r = record(self.key, self.bond)
        r["bond"]["notice"] = "%08x" % B.notice_sequence(86400)
        self.refused(r, "bond.notice")

    def test_refuses_a_script_its_terms_do_not_derive(self):
        r = record(self.key, self.bond)
        r["bond"]["bonded"] = r["bond"]["noticed"]
        self.refused(r, "bond.bonded")

    def test_refuses_a_record_that_hides_its_bond(self):
        self.refused(record(self.key, None), "leaves it out")

    def test_refuses_version_1_and_unknown_fields_and_floats(self):
        self.refused(record(self.key, self.bond, version=1), "version 2")
        self.refused(record(self.key, self.bond, extra=1), "fields a registry does not know")
        r = record(self.key, self.bond)
        r["bond"]["notice_seconds"] = 2592000.0
        self.refused(r, "bond.notice_seconds")
        r = record(self.key, self.bond, beacon_asset="AB" * 32)
        self.refused(r, "beacon_asset")


class Example(unittest.TestCase):
    """vectors/registry-record.json: a record signed with a public test key,
    which sequentia-registry's tests verify with their own code."""

    def test_the_example_verifies_and_is_reproduced(self):
        with open(EXAMPLE) as f:
            ex = json.load(f)
        self.assertTrue(R.verify(ex["signed"]))
        sec = bytes.fromhex(ex["secret"])
        key = A.xonly_pubkey(sec)
        bond = B.Bond(key, ex["signed"]["record"]["bond"]["asset"],
                      int(ex["signed"]["record"]["bond"]["notice"], 16))
        R.check(ex["signed"]["record"], key, bond)
        self.assertEqual(R.sign(sec, ex["signed"]["record"]), ex["signed"])
        self.assertEqual(R.record_hash(ex["signed"]["record"]).hex(), ex["record_hash"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--write-example":
        sec = bytes([0x4b]) * 32
        key = A.xonly_pubkey(sec)
        bond = B.Bond(key, USDX, B.notice_sequence(2592000))
        r = record(key, bond)
        signed = R.sign(sec, r)
        with open(EXAMPLE, "w") as f:
            json.dump({"_note": "A public test key, never used for anything but this example. The record is "
                                "signed with BIP340 (aux all zero) over tagged('" + R.TAG + "', canonical JSON).",
                       "secret": sec.hex(), "record_hash": R.record_hash(r).hex(), "signed": signed},
                      f, indent=1, sort_keys=True)
            f.write("\n")
        print("wrote", EXAMPLE)
        sys.exit(0)
    unittest.main()
