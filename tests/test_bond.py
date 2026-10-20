#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The bond without a node: the vendored template, the rule's vectors, what the
key signs for its bond, the transaction codec, and what the watcher counts as
a conflict."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from sequentia_oracle import attestation as A     # noqa: E402
from sequentia_oracle import bond as B            # noqa: E402
from sequentia_oracle import signer as S          # noqa: E402
from sequentia_oracle import tx as T              # noqa: E402
from sequentia_oracle import watcher as W         # noqa: E402

VENDOR = os.path.join(ROOT, "sequentia_oracle", "sequentia_contracts")


def load(path):
    with open(path) as f:
        return json.load(f)


VEC = load(os.path.join(ROOT, "vectors", "attestations.json"))
SEC_A = bytes.fromhex(VEC["keys"]["A"]["secret"])
SEC_B = bytes.fromhex(VEC["keys"]["B"]["secret"])
KEY_A = A.xonly_pubkey(SEC_A)
KEY_B = A.xonly_pubkey(SEC_B)
GOLD = A.asset_from_display(VEC["assets_display"]["GOLD"])
USDX = A.asset_from_display(VEC["assets_display"]["USDX"])
SILVR = A.asset_from_display(VEC["assets_display"]["SILVR"])


def att(sec, price, time, quote=USDX, precision=5, beacon=A.NO_BEACON, base=GOLD):
    a = A.AttestationV2(A.xonly_pubkey(sec), base, quote, price, precision, time, beacon)
    return a.sign(sec, aux=os.urandom(32)).to_dict()


class Vendored(unittest.TestCase):
    def test_the_files_are_the_pinned_copies(self):
        pin = load(os.path.join(VENDOR, "PIN.json"))
        self.assertEqual(len(pin["commit"]), 40)
        for name, f in pin["files"].items():
            with open(os.path.join(VENDOR, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), f["sha256"], name)
        self.assertEqual(B.TEMPLATE_HASH, load(os.path.join(
            VENDOR, "templates", "oracle_bond", "descriptor.json"))["template_hash"])

    def test_bonds_derive_the_vectors(self):
        v = load(os.path.join(B.TEMPLATE_DIR, "vectors.json"))
        for e in v["addresses"]:
            p = e["params"]
            b = B.Bond(p["ORACLE"], A.asset_to_display(bytes.fromhex(p["BOND_ASSET"])), int(p["NOTICE"], 16))
            st = int(e["slots"]["STATE"], 16)
            self.assertEqual(b.spk(st), e["script_pubkey"], e["name"])
            self.assertEqual(b.control_block(st), e["leaves"]["bond"]["control_block"], e["name"])
            self.assertEqual(b.address(st, "tb"), e["address"]["sequentia-testnet"], e["name"])

    def test_the_rule_vectors(self):
        r = load(os.path.join(B.TEMPLATE_DIR, "rules.json"))
        for c in r["conflict"]:
            got = B.conflict(bytes.fromhex(c["bonded"]), {"message": c["m1"], "signature": c["s1"]},
                             {"message": c["m2"], "signature": c["s2"]})
            self.assertEqual(got, c["reason"], c["name"])
        for d in r["digests"]:
            disp = lambda h: bytes.fromhex(h)[::-1].hex()
            dest = bytes.fromhex(d["dest"]) if d["dest"] else None
            got = B.digest(d["kind"], disp(d["genesis"]), disp(d["txid"]), d["vout"], dest)
            self.assertEqual(got.hex(), d["digest"], d["name"])
            self.assertTrue(A.schnorr_verify(bytes.fromhex(d["key"]), got, bytes.fromhex(d["signature"])))


class Notice(unittest.TestCase):
    def test_sequence(self):
        self.assertEqual(B.notice_sequence(1024), (1 << 22) | 2)
        self.assertEqual(B.notice_sequence(1025), (1 << 22) | 3)
        self.assertEqual(B.notice_seconds(B.notice_sequence(30 * 86400)), 5063 * 512)
        for bad in (0, -1, 65536 * 512):
            with self.assertRaises(B.BondError):
                B.notice_sequence(bad)
        for bad in (2, 0x80400002, (1 << 22) | (1 << 23) | 2):
            with self.assertRaisesRegex(B.BondError, "not a time-based relative lock"):
                B.notice_seconds(bad)
            with self.assertRaises(B.BondError):
                B.Bond(KEY_A, "11" * 32, bad)


class Signatures(unittest.TestCase):
    G = "dd" * 32
    TX = "ee" * 32

    def test_a_record_is_what_it_says(self):
        n = B.sign_record(SEC_A, "notice", self.G, self.TX, 1)
        self.assertTrue(B.record_ok(KEY_A, n))
        self.assertFalse(B.record_ok(KEY_B, n), "another key")
        for k, v in (("vout", 2), ("txid", "ef" * 32), ("genesis", "de" * 32), ("kind", "withdraw")):
            self.assertFalse(B.record_ok(KEY_A, dict(n, **{k: v})), k)
        w = B.sign_record(SEC_A, "withdraw", self.G, self.TX, 1, "5120" + "77" * 32)
        self.assertTrue(B.record_ok(KEY_A, w))
        self.assertFalse(B.record_ok(KEY_A, dict(w, to="5120" + "78" * 32)), "another destination")
        self.assertFalse(B.record_ok(KEY_A, dict(w, kind="notice")), "a withdrawal as a notice")
        self.assertFalse(B.record_ok(KEY_A, dict(n, kind="withdraw", to=w["to"], dest=w["dest"])),
                         "a notice as a withdrawal")
        # Neither is a price, nor a price one of them.
        price = A.AttestationV2.decode(bytes.fromhex(att(SEC_A, 1, 1)["message"]))
        self.assertNotEqual(price.digest().hex(), n["digest"])

    def test_the_slash_witness(self):
        r1, r2 = att(SEC_A, 300, 1790000000), att(SEC_A, 240, 1790000000, beacon=b"\x05" * 32)
        p = B.slash_path(r1, r2)
        self.assertIn("1790000000, (300, 0x%s" % ("00" * 32), p)
        self.assertIn("(240, 0x%s, 0x%s)" % ("05" * 32, r2["signature"]), p)


class Codec(unittest.TestCase):
    def test_round_trip(self):
        t = T.Tx(locktime=7)
        t.vin.append(T.TxIn("aa" * 32, 3, 0x00400002))
        t.vin.append(T.TxIn("bb" * 32, 0, 0xfffffffe))
        t.vout = [T.TxOut("cc" * 32, 5, b"\x6a"), T.TxOut("cc" * 32, 2 ** 64 - 1, bytes.fromhex("5120" + "11" * 32)),
                  T.TxOut("dd" * 32, 1000, b"")]
        bare = t.serialize()
        self.assertEqual(bare[4], 0, "no witness, flags 0")
        t.vin[0].witness = [b"\x01" * 100, b"", b"\x02"]
        full = t.serialize()
        back = T.Tx.parse(full.hex())
        self.assertEqual(back.serialize(), full)
        self.assertEqual(back.txid(), t.txid())
        self.assertEqual(back.vin[0].witness, [b"\x01" * 100, b"", b"\x02"])
        self.assertEqual(back.vout[1].amount, 2 ** 64 - 1)
        with self.assertRaises(T.TxError):
            T.Tx.parse(full + b"\x00")
        conf = bytearray(full)
        i = full.index(bytes.fromhex("01" + "cc" * 32))
        conf[i] = 0x0a
        with self.assertRaisesRegex(T.TxError, "confidential"):
            T.Tx.parse(bytes(conf))


class Conflicts(unittest.TestCase):
    """The watcher's index: only a pair the template slashes for is a conflict."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="seqbond-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def watch(self, records, key=KEY_A):
        path = os.path.join(self.dir, "log")
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        w = W.Watcher.__new__(W.Watcher)
        w.state, w.retain, w.timeout = {"seen": {}, "conflicts": [], "slashed": {}}, 1e12, 5
        return w.read({"key": key.hex(), "logs": [path]})

    def test_what_is_and_is_not_a_conflict(self):
        t = 1790000000
        honest = att(SEC_A, 300, t)
        self.assertEqual(self.watch([honest]), {})
        self.assertEqual(self.watch([honest, att(SEC_A, 240, t + 1)]), {}, "two times")
        self.assertEqual(self.watch([honest, att(SEC_A, 300, t, beacon=b"\x09" * 32)]), {}, "one price twice")
        self.assertEqual(self.watch([honest, att(SEC_A, 240, t, quote=SILVR)]), {}, "another pair")
        self.assertEqual(self.watch([honest, att(SEC_A, 2400, t, precision=6)]), {}, "another precision")
        self.assertEqual(self.watch([honest, att(SEC_B, 240, t)]), {}, "another key")
        forged = dict(att(SEC_B, 240, t), key=KEY_A.hex())
        forged["message"] = "02" + KEY_A.hex() + forged["message"][66:]
        self.assertEqual(self.watch([honest, forged]), {}, "the bonded key named, another's signature")
        lie = att(SEC_A, 240, t, beacon=b"\x09" * 32)
        found = self.watch([honest, lie])
        self.assertEqual(len(found), 1)
        (feed, prices), = found.items()
        self.assertEqual(sorted(prices, key=int), ["240", "300"])
        r1, r2 = [prices[p] for p in ("240", "300")]
        self.assertIsNone(B.conflict(KEY_A, r1, r2))

    def test_sources(self):
        recs = [att(SEC_A, 300, 1), att(SEC_A, 301, 2)]
        for name, text in (("nd", "\n".join(json.dumps(r) for r in recs)), ("list", json.dumps(recs)),
                           ("obj", json.dumps({"attestations": recs}))):
            p = os.path.join(self.dir, name)
            with open(p, "w") as f:
                f.write(text)
            self.assertEqual([r["message"] for r in W.fetch(p)], [r["message"] for r in recs], name)


class SignerBond(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="seqbond-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def cfg(self, **over):
        c = {"keyfile": os.path.join(self.dir, "oracle.key"), "formats": [2], "markets": ["GOLD/USDX"],
             "assets": {"GOLD": "aa" * 32, "USDX": "bb" * 32}, "precisions": {"GOLD": 8, "USDX": 8},
             "source": {"type": "static", "prices": {"GOLD": 3000, "USDX": 1}},
             "bond": {"asset": "bb" * 32, "notice": 30 * 86400}}
        c.update(over)
        return c

    def test_declared_once_and_signs_for_its_coins(self):
        s = S.Signer(self.cfg(), create_key=True)
        rec = s.declare_bond()
        self.assertEqual(rec["kind"], "bond")
        self.assertIsNone(s.declare_bond(), "the same terms are not declared twice")
        self.assertEqual(B.declared(B.read_log(s.bond_log))[0].spk(B.BONDED), rec["bonded"])
        n = s.sign_bond("notice", "aa" * 32 + ":0", "cc" * 32)
        self.assertTrue(B.record_ok(s.key, n))
        w = s.sign_bond("withdraw", "aa" * 32 + ":1", "cc" * 32, "0014" + "33" * 20)
        self.assertTrue(B.record_ok(s.key, w))
        self.assertEqual([r["kind"] for r in B.read_log(s.bond_log)], ["bond", "notice", "withdraw"])
        with self.assertRaises(S.ConfigError):
            s.sign_bond("notice", "zz:0", "cc" * 32)
        with self.assertRaises(S.ConfigError):
            s.sign_bond("withdraw", "aa" * 32 + ":1", "cc" * 32)
        # New terms are a new declaration; the old one stays on record.
        s2 = S.Signer(self.cfg(bond={"asset": "bb" * 32, "notice": 60 * 86400}))
        self.assertIsNotNone(s2.declare_bond())
        self.assertEqual(len(B.declared(B.read_log(s.bond_log))), 2)

    def test_bond_refusals(self):
        S.Signer(self.cfg(), create_key=True)
        for bad, why in (({"asset": "bb" * 32}, "bond.notice is required"),
                         ({"notice": 86400}, "bond.asset is required"),
                         ({"asset": "bb" * 32, "notice": 0}, "positive"),
                         ({"asset": "bb" * 32, "notice": 86400, "amount": 1}, "does not understand")):
            with self.assertRaisesRegex(S.ConfigError, why):
                S.Signer(self.cfg(bond=bad))
        with self.assertRaisesRegex(S.ConfigError, "format-2"):
            S.Signer(self.cfg(formats=[1]))

    def test_two_markets_of_one_pair_are_refused(self):
        with self.assertRaisesRegex(S.ConfigError, "name the same pair"):
            S.Signer(self.cfg(markets=["GOLD/USDX", "XAU/USDX"],
                              assets={"GOLD": "aa" * 32, "XAU": "aa" * 32, "USDX": "bb" * 32},
                              precisions={"GOLD": 8, "XAU": 8, "USDX": 8}), create_key=True)

    def test_one_signer_per_key_file(self):
        a = S.Signer(self.cfg(), create_key=True)
        a.lock()
        b = S.Signer(self.cfg(log_v2=os.path.join(self.dir, "other-v2.log")))
        with self.assertRaisesRegex(S.ConfigError, "One key, one signer"):
            b.lock()

    def test_the_command(self):
        path = os.path.join(self.dir, "signer.json")
        with open(path, "w") as f:
            json.dump(self.cfg(), f)
        S.Signer(self.cfg(), create_key=True)
        cmd = [sys.executable, os.path.join(ROOT, "bin", "sequentia-oracle-signer"), "--config", path]
        out = subprocess.run(cmd + ["--bond-notice", "ab" * 32 + ":3", "--genesis", "cd" * 32],
                             capture_output=True, text=True, check=True).stdout
        n = json.loads(out)
        self.assertEqual((n["kind"], n["vout"]), ("notice", 3))
        key = bytes.fromhex(subprocess.run(cmd + ["--print-pubkey"], capture_output=True, text=True,
                                           check=True).stdout.strip())
        self.assertTrue(B.record_ok(key, n))
        bad = subprocess.run(cmd + ["--bond-withdraw", "ab" * 32 + ":3", "--genesis", "cd" * 32],
                             capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
