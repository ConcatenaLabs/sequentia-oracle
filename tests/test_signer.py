#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The signer as a process: what it signs, in which formats, and what it will not.

The feed is a local HTTP server, so every price below is known exactly.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from sequentia_oracle import attestation as A    # noqa: E402
from sequentia_oracle import feed as F           # noqa: E402
from sequentia_oracle import signer as S         # noqa: E402

BIN = os.path.join(ROOT, "bin", "sequentia-oracle-signer")
GOLD = "aa" * 32
USDX = "bb" * 32
FEED = {"tBTC": 60000, "GOLD": {"price": 3000}, "USDX": {"price": 1}}


# A registry's minimal index: asset id -> [.., ticker, name, precision].
REGISTRY = {GOLD: [0, "GOLD", "Gold", 8], USDX: [0, "USDX", "Dollar", 8],
            "cc" * 32: [0, "TWIN", "One", 8], "dd" * 32: [0, "TWIN", "Two", 8]}


class Feed(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/index.minimal.json":
            body = json.dumps(REGISTRY).encode()
        else:
            body = json.dumps({**FEED, "_meta": {"updated": int(time.time())}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SignerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", cls.port), Feed)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="seqoracle-")
        FEED.update({"tBTC": 60000, "GOLD": {"price": 3000}, "USDX": {"price": 1}})

    def tearDown(self):
        shutil.rmtree(self.dir)

    def cfg(self, **over):
        c = {
            "keyfile": os.path.join(self.dir, "oracle.key"),
            "interval": 1,
            "markets": ["GOLD/USDX", "BTC/USDX"],
            "assets": {"GOLD": GOLD, "USDX": USDX, "BTC": "unit:BTC"},
            "precisions": {"GOLD": 8, "USDX": 2, "BTC": 8},
            "symbols": {"BTC": "tBTC"},
            "precision": 5,
            "flat_rounds": 0,
            "source": {"type": "http_bulk", "url": f"http://127.0.0.1:{self.port}/prices"},
        }
        c.update(over)
        return c

    def logs(self, signer):
        def read(p):
            if not os.path.exists(p):
                return []
            with open(p) as f:
                return [json.loads(x) for x in f if x.strip()]
        return read(signer.log_v1), read(signer.log_v2)

    def test_one_round_signs_both_formats_for_one_observation(self):
        s = S.Signer(self.cfg(), create_key=True)
        self.assertEqual(oct(os.stat(self.cfg()["keyfile"]).st_mode & 0o777), "0o600")
        self.assertEqual(s.tick(), 2)
        v1, v2 = self.logs(s)
        self.assertEqual(len(v1), 2)
        self.assertEqual(len(v2), 2)
        by1 = {d["market"]: d for d in v1}
        by2 = {d["market"]: d for d in v2}
        # GOLD at 3,000 USD in a 2-decimal USDX: a GOLD atom buys
        # 3000 * 10^(2-8) = 0.003 USDX atoms, times 10^5.
        self.assertEqual(by1["GOLD/USDX"]["price"], 300)
        self.assertEqual(by1["BTC/USDX"]["price"], 6000)
        for m in ("GOLD/USDX", "BTC/USDX"):
            a1, d2 = by1[m], by2[m]
            att = A.AttestationV2.from_dict(d2)
            self.assertTrue(att.verify(s.key), m)
            self.assertTrue(A.v1_verify(s.key, a1), m)
            self.assertEqual((a1["timestamp"], a1["price"], a1["price_scale"]),
                             (att.time, att.price, 10 ** att.precision), m)
            self.assertEqual(A.v1_line(a1), json.dumps(a1, sort_keys=True, separators=(",", ":")))
        g = A.AttestationV2.from_dict(by2["GOLD/USDX"])
        self.assertEqual(g.base, bytes.fromhex(GOLD)[::-1])
        self.assertEqual(g.quote, bytes.fromhex(USDX)[::-1])
        self.assertEqual(A.AttestationV2.from_dict(by2["BTC/USDX"]).base, A.unit_id("BTC"))
        with open(s.status_path) as f:
            st = json.load(f)
        self.assertEqual(st["key"], s.key.hex())
        self.assertEqual(st["markets"]["GOLD/USDX"]["price"], 300)

    def test_an_observation_is_signed_once(self):
        s = S.Signer(self.cfg(), create_key=True)
        s.tick()
        # The feed stamps each answer with the second it is served; a round in
        # the same second with the same prices has nothing new to sign.
        observed = s.source.observed_at()
        s.source.observed_at = lambda: observed
        self.assertEqual(s.tick(), 0)
        FEED["GOLD"] = {"price": 3100}
        self.assertEqual(s.tick(), 1)
        # A restarted signer reads its logs back and does not sign it again.
        s2 = S.Signer(self.cfg())
        s2.source.refresh = lambda: None
        s2.source._snapshot = s.source._snapshot
        s2.source._fetched = s.source._fetched
        s2.source._updated = s.source._updated
        s2.source.observed_at = lambda: observed
        self.assertEqual(s2.tick(), 0)
        v1, v2 = self.logs(s2)
        self.assertEqual((len(v1), len(v2)), (3, 3))

    def test_formats_can_be_one_or_the_other(self):
        s = S.Signer(self.cfg(formats=[2]), create_key=True)
        s.tick()
        v1, v2 = self.logs(s)
        self.assertEqual((len(v1), len(v2)), (0, 2))
        cfg = self.cfg(formats=[1], keyfile=os.path.join(self.dir, "v1only", "oracle.key"))
        cfg.pop("assets")
        s = S.Signer(cfg, create_key=True)
        s.tick()
        v1, _ = self.logs(s)
        self.assertEqual(len(v1), 2)

    def test_a_jump_is_held_until_it_holds(self):
        s = S.Signer(self.cfg(max_jump=0.5, jump_rounds=3), create_key=True)
        s.tick()
        FEED["GOLD"] = {"price": 30000}          # tenfold: a feed that changed units
        for _ in range(2):
            time.sleep(1.05)
            s.tick()
            self.assertIn("max_jump", s.errors.get("GOLD/USDX", ""))
        time.sleep(1.05)
        s.tick()
        self.assertNotIn("GOLD/USDX", s.errors)
        self.assertEqual(s.latest["GOLD/USDX"][1], 3000)

    def test_a_frozen_board_is_not_signed(self):
        s = S.Signer(self.cfg(flat_rounds=2), create_key=True)
        s.tick()
        time.sleep(1.05)
        s.tick()
        self.assertTrue(s.frozen)
        self.assertIn("same price", s.errors["GOLD/USDX"])
        v1, v2 = self.logs(s)
        self.assertEqual((len(v1), len(v2)), (2, 2))

    def test_config_refusals(self):
        def refused(cfg, text, create=True):
            with self.assertRaises(SystemExit) as cm:
                S.Signer(cfg, create_key=create)
            self.assertIn(text, str(cm.exception))
        refused(self.cfg(precisions={"GOLD": 8}), "precisions missing for BTC, USDX")
        refused(self.cfg(assets={"GOLD": GOLD}), "assets missing for BTC, USDX")
        refused(self.cfg(assets={"GOLD": GOLD, "USDX": GOLD, "BTC": "unit:BTC"}), "same asset")
        refused(self.cfg(assets={"GOLD": "xyz", "USDX": USDX, "BTC": "unit:BTC"}), "64 hex")
        refused(self.cfg(precision=19), "precision must be")
        refused(self.cfg(formats=[3]), "formats")
        refused(self.cfg(source={"type": "http_bulk", "url": "http://198.51.100.1/p"}), "plain http")
        refused(self.cfg(source={"type": "static", "prices": {}, "url": "x"}), "does not understand")
        with self.assertRaises(SystemExit):
            path = os.path.join(self.dir, "c.json")
            with open(path, "w") as f:
                json.dump(dict(self.cfg(), price_scale=100000), f)
            S.load_config(path)
        refused(self.cfg(), "no oracle key", create=False)
        self.assertFalse(os.path.exists(self.cfg()["keyfile"]))

    def test_key_rules(self):
        s = S.Signer(self.cfg(), create_key=True)
        s.tick()
        key = self.cfg()["keyfile"]
        os.chmod(key, 0o640)
        with self.assertRaises(SystemExit) as cm:
            S.Signer(self.cfg())
        self.assertIn("readable by other users", str(cm.exception))
        os.chmod(key, 0o600)
        os.rename(key, key + ".moved")
        with self.assertRaises(SystemExit) as cm:
            S.Signer(self.cfg(), create_key=True)
        self.assertIn("has signed before", str(cm.exception))
        self.assertFalse(os.path.exists(key))
        with open(key, "w") as f:
            f.write("00" * 32)
        os.chmod(key, 0o600)
        with self.assertRaises(SystemExit) as cm:
            S.Signer(self.cfg())
        self.assertIn("usable key", str(cm.exception))

    def test_one_signer_per_log(self):
        a = S.Signer(self.cfg(), create_key=True)
        a.lock()
        b = S.Signer(self.cfg())
        with self.assertRaises(SystemExit) as cm:
            b.lock()
        self.assertIn("another signer", str(cm.exception))

    # ------------------------------------------------------------- the beacon

    def beacon_cfg(self, **b):
        return self.cfg(beacon=dict({"rotate_every": 0}, **b))

    def read_beacon(self, s):
        with open(s.beacon_log) as f:
            return [json.loads(x) for x in f if x.strip()]

    def test_every_record_names_the_current_beacon(self):
        s = S.Signer(self.beacon_cfg(), create_key=True)
        self.assertEqual(s.tick(), 2)
        epochs = A.beacon_epochs(s.key, self.read_beacon(s))
        self.assertEqual(len(epochs), 1)
        b1 = epochs[0]["program"]
        self.assertNotEqual(b1, A.NO_BEACON)
        self.assertEqual(b1, A.BeaconScript(s.key, epochs[0]["nonce"]).program)
        _, v2 = self.logs(s)
        for d in v2:
            att = A.AttestationV2.from_dict(d)
            self.assertTrue(att.verify(s.key))
            self.assertEqual(att.beacon, b1)
        with open(s.status_path) as f:
            st = json.load(f)
        self.assertEqual(st["beacon"]["program"], b1.hex())
        self.assertEqual(st["beacon"]["epoch"], 0)

    def test_a_request_rotates_and_the_observation_is_signed_again(self):
        s = S.Signer(self.beacon_cfg(), create_key=True)
        s.tick()
        observed = s.source.observed_at()
        s.source.observed_at = lambda: observed
        self.assertEqual(s.tick(), 0)             # nothing new, no request
        with open(s.beacon_request, "w") as f:
            f.write("")
        self.assertEqual(s.tick(), 2)             # the same observation, new beacon
        self.assertFalse(os.path.exists(s.beacon_request))
        epochs = A.beacon_epochs(s.key, self.read_beacon(s))
        self.assertEqual(len(epochs), 2)
        b1, b2 = epochs[0]["program"], epochs[1]["program"]
        self.assertTrue(A.rotation_verify(s.key, b1, b2, epochs[1]["signature"]))
        v1, v2 = self.logs(s)
        # format 1 has no beacon: its record is not written twice
        self.assertEqual((len(v1), len(v2)), (2, 4))
        olds = [A.AttestationV2.from_dict(d) for d in v2[:2]]
        news = [A.AttestationV2.from_dict(d) for d in v2[2:]]
        for o, n in zip(olds, news):
            self.assertEqual((o.price, o.time, o.beacon), (n.price, n.time, b1))
            self.assertEqual(n.beacon, b2)
        self.assertEqual(s.tick(), 0)
        # A restart finds epoch 1 and does not sign the observation a third time.
        s2 = S.Signer(self.beacon_cfg())
        self.assertEqual(s2.beacon, b2)
        s2.source.refresh = lambda: None
        s2.source._snapshot = s.source._snapshot
        s2.source._fetched = s.source._fetched
        s2.source._updated = s.source._updated
        s2.source.observed_at = lambda: observed
        self.assertEqual(s2.tick(), 0)

    def test_the_schedule_rotates(self):
        s = S.Signer(self.beacon_cfg(rotate_every=600), create_key=True)
        s.tick()
        t0 = s.epochs[-1]["time"]
        self.assertFalse(s.maybe_rotate(now=t0 + 599))
        self.assertTrue(s.maybe_rotate(now=t0 + 600))
        self.assertEqual(len(A.beacon_epochs(s.key, self.read_beacon(s))), 2)
        # every rotation is to a program never used before
        for _ in range(3):
            self.assertTrue(s.maybe_rotate(now=time.time() + 10_000))
        progs = [e["program"] for e in A.beacon_epochs(s.key, self.read_beacon(s))]
        self.assertEqual(len(set(progs)), 5)

    def test_beacon_refusals(self):
        def refused(cfg, text):
            with self.assertRaises(SystemExit) as cm:
                S.Signer(cfg, create_key=True)
            self.assertIn(text, str(cm.exception))
        refused(self.cfg(beacon={"every": 5}), "does not understand every")
        refused(self.cfg(beacon={}, formats=[1]), "add 2 to `formats`")
        s = S.Signer(self.beacon_cfg(), create_key=True)
        s.tick()
        with open(s.beacon_request, "w") as f:
            f.write("")
        s.tick()
        log = s.beacon_log
        with open(log) as f:
            lines = f.read().splitlines()
        # a rotation whose signature is another's
        d = json.loads(lines[1])
        d["signature"] = "00" * 64
        with open(log, "w") as f:
            f.write(lines[0] + "\n" + json.dumps(d) + "\n")
        refused(self.beacon_cfg(), "rotation signature does not verify")
        # a program its nonce does not derive
        d = json.loads(lines[1])
        d["nonce"] = "11" * 32
        with open(log, "w") as f:
            f.write(lines[0] + "\n" + json.dumps(d) + "\n")
        refused(self.beacon_cfg(), "not its nonce's")
        # the beacon log lost while the format-2 log names a beacon
        os.unlink(log)
        refused(self.beacon_cfg(), "Restore the beacon log")

    def test_the_command(self):
        path = os.path.join(self.dir, "signer.json")
        with open(path, "w") as f:
            json.dump(self.cfg(), f)
        r = subprocess.run([sys.executable, BIN, "--config", path, "--print-pubkey"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no oracle key", r.stderr)
        r = subprocess.run([sys.executable, BIN, "--config", path, "--create-key", "--once"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["signed"], 2)
        self.assertIn("CREATED a new key", r.stderr)
        r = subprocess.run([sys.executable, BIN, "--config", path, "--print-pubkey"],
                           capture_output=True, text=True)
        key = r.stdout.strip()
        with open(os.path.join(self.dir, "attestations-v2.log")) as f:
            for line in f:
                self.assertTrue(A.AttestationV2.from_dict(json.loads(line)).verify(bytes.fromhex(key)))
        # The key never reaches stdout, stderr or a log.
        def text(path):
            with open(path) as f:
                return f.read()
        secret = text(self.cfg()["keyfile"]).strip()
        for name in os.listdir(self.dir):
            if name != "oracle.key" and os.path.isfile(os.path.join(self.dir, name)):
                self.assertNotIn(secret, text(os.path.join(self.dir, name)), name)
        self.assertNotIn(secret, r.stdout + r.stderr)

    def test_the_example_configuration_is_one_the_signer_takes(self):
        cfg = S.load_config(os.path.join(ROOT, "deploy", "signer.example.json"))
        cfg.update(keyfile=os.path.join(self.dir, "oracle.key"), log_v1=None,
                   log_v2=None, status=None)
        s = S.Signer(cfg, create_key=True)
        self.assertEqual(s.formats, [1, 2])
        self.assertEqual(s.price_scale, 100_000)
        self.assertEqual(s.refs["BTC"], A.unit_id("BTC"))

    def test_asset_ids_from_a_registry(self):
        tool = os.path.join(ROOT, "tools", "resolve_assets.py")
        reg = f"http://127.0.0.1:{self.port}"
        r = subprocess.run([sys.executable, tool, "--registry", reg, "GOLD", "USDX", "BTC=unit:BTC"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"GOLD": GOLD, "USDX": USDX, "BTC": "unit:BTC"})
        r = subprocess.run([sys.executable, tool, "--registry", reg, "TWIN", "NONE"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("lists 2 assets with ticker TWIN", r.stderr)
        self.assertIn("lists 0 assets with ticker NONE", r.stderr)

    def test_quote_price_worked_example(self):
        self.assertEqual(F.quote_price(3000, 1, 8, 8, 100_000), 300_000_000)
        self.assertEqual(S.precision_of_scale(100_000), 5)
        with self.assertRaises(ValueError):
            S.precision_of_scale(250)


if __name__ == "__main__":
    unittest.main(verbosity=2)
