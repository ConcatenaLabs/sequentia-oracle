#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The bond on a regtest chain: the signer, the bond tool and the watcher as
processes, against a node with Simplicity active.

    SEQUENTIAD=<Sequentia>/src/sequentiad SEQC=<sequentia-contracts>/target/release/seqc \
        python3 tests/test_bond_regtest.py

Skipped without both. The node runs a custom chain (`elementsregtest`), on
ports it finds free below 32768, with its data in a temporary directory
(under SEQ_TEST_TMP when set); it is stopped at the end.

  1. The signer declares its bond and signs a price; the bond tool posts a
     coin and tops it up from an operating wallet, and refuses a treasury one.
  2. Notice on one coin: the tool asks for the key's signature, the signer
     makes it, the tool sends it. A withdrawal before the notice has run is
     refused by the tool and, forced into a block, by consensus
     (bad-txns-nonfinal); after it, the coin goes to the address the key named.
  3. The watcher reads the signer's log and a second source. Records there
     that are no conflict (another time, the same price under another beacon,
     another pair, another precision, another key's two prices) slash
     nothing. Then the oracle's second price for the logged pair and time
     appears, and the watcher slashes every coin of the bond, bonded and in
     notice: half burned, the rest to the watcher's address.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from sequentia_oracle import attestation as A     # noqa: E402
from sequentia_oracle import bond as B            # noqa: E402
from sequentia_oracle import rpc as R             # noqa: E402
from sequentia_oracle import tx as T              # noqa: E402

SEQUENTIAD = os.environ.get("SEQUENTIAD")
SEQC = os.environ.get("SEQC")
BIN = os.path.join(ROOT, "bin")
GOLD, USDX, SILVR = "aa" * 32, "bb" * 32, "cc" * 32
NOTICE = 1024
EVIDENCE = os.environ.get("BOND_EVIDENCE")


def free_port(start):
    for p in range(start, start + 2000):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("no free port")


def run(*args, ok=True):
    p = subprocess.run([sys.executable] + list(args), capture_output=True, text=True)
    if ok and p.returncode != 0:
        raise AssertionError(f"{args[0]} failed ({p.returncode}): {p.stderr[-1500:]}")
    return p


@unittest.skipUnless(SEQUENTIAD and SEQC and os.path.exists(SEQUENTIAD) and os.path.exists(SEQC),
                     "SEQUENTIAD and SEQC name a node and seqc")
class BondOnRegtest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="seqbond-rt-", dir=os.environ.get("SEQ_TEST_TMP"))
        cls.rpcport = free_port(21500)
        cls.p2p = free_port(cls.rpcport + 1)
        data = os.path.join(cls.dir, "node")
        os.makedirs(data)
        cls.proc = subprocess.Popen(
            [SEQUENTIAD, "-chain=elementsregtest", f"-datadir={data}", f"-rpcport={cls.rpcport}",
             f"-port={cls.p2p}", "-listen=0", "-connect=0", "-server", "-par=1",
             "-initialfreecoins=2100000000000000", "-anyonecanspendaremine=1", "-blindedaddresses=0",
             "-con_default_blinded_addresses=0", "-validatepegin=0", "-con_parent_chain_signblockscript=51",
             "-con_any_asset_fees=1", "-evbparams=simplicity:-1:::", "-fallbackfee=0"],
            # No fallback fee, as on the testnet's nodes: every send the tools
            # make states its rate, and only the test's own funder carries one.
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cookie = os.path.join(data, "elementsregtest", ".cookie")
        cls.url = f"http://127.0.0.1:{cls.rpcport}"
        for _ in range(300):
            if os.path.exists(cls.cookie):
                try:
                    R.Node(cls.url, cls.cookie).call("getblockcount", wallet=False)
                    break
                except Exception:                     # noqa: BLE001 - starting
                    pass
            time.sleep(0.2)
        cls.root = R.Node(cls.url, cls.cookie)
        cls.ev = {"node": subprocess.run([SEQUENTIAD, "-version"], capture_output=True, text=True).stdout.splitlines()[0],
                  "pid": cls.proc.pid}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.call("stop", wallet=False)
            cls.proc.wait(timeout=60)
        except Exception:                             # noqa: BLE001
            cls.proc.terminate()
            cls.proc.wait(timeout=30)
        if EVIDENCE:
            with open(EVIDENCE, "w") as f:
                json.dump(cls.ev, f, indent=1, sort_keys=True, default=str)
        shutil.rmtree(cls.dir)

    def wallet(self, name):
        self.root.call("createwallet", name, wallet=False)
        return R.Node(self.url, self.cookie, wallet=name)

    def mine(self, n=1):
        self.funder.generatetoaddress(n, self.funder.getnewaddress())

    def advance(self, seconds):
        tip = self.root.call("getblockheader", self.root.call("getbestblockhash", wallet=False), wallet=False)["time"]
        self.root.call("setmocktime", tip + seconds, wallet=False)
        self.mine(12)

    def write(self, name, obj):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def test_bond_notice_withdrawal_and_slash(self):
        ev = self.ev
        self.funder = self.wallet("funder")
        self.funder.rescanblockchain()
        self.funder.call("settxfee", 0.00002)
        self.mine(1)
        bond_asset = self.funder.call("issueasset", assetamount=100000, tokenamount=0, blind=False,
                                      fee_asset="bitcoin")["asset"]
        self.mine(1)
        self.root.call("setfeeexchangerates", {"bitcoin": 100000000, bond_asset: 100000000}, wallet=False)
        ops, watch, recv = self.wallet("oracle-ops"), self.wallet("watcher"), self.wallet("receiver")
        for a, amt in ((bond_asset, 5000), ("bitcoin", 10)):
            self.funder.call("sendtoaddress", address=ops.getnewaddress(), amount=amt, assetlabel=a,
                             fee_asset_label="bitcoin")
        self.mine(1)
        ev["bond_asset"] = bond_asset

        # -- 1. the signer declares the bond and signs; the tool posts it -------------
        signer_cfg = self.write("signer.json", {
            "keyfile": os.path.join(self.dir, "oracle", "oracle.key"), "formats": [2], "markets": ["GOLD/USDX"],
            "assets": {"GOLD": GOLD, "USDX": USDX}, "precisions": {"GOLD": 8, "USDX": 8}, "precision": 5,
            "source": {"type": "static", "prices": {"GOLD": 3000, "USDX": 1}},
            "bond": {"asset": bond_asset, "notice": NOTICE}})
        signer = os.path.join(BIN, "sequentia-oracle-signer")
        run(signer, "--config", signer_cfg, "--create-key", "--once")
        key = bytes.fromhex(run(signer, "--config", signer_cfg, "--print-pubkey").stdout.strip())
        oracle_dir = os.path.join(self.dir, "oracle")
        log_v2, bond_log = os.path.join(oracle_dir, "attestations-v2.log"), os.path.join(oracle_dir, "bond.log")
        honest = B.read_log(log_v2)[-1]
        decl = B.read_log(bond_log)[0]
        self.assertEqual((decl["kind"], decl["asset"], decl["notice"]), ("bond", bond_asset, "%08x" % B.notice_sequence(NOTICE)))
        ev["declaration"] = decl
        ev["honest_record"] = {k: honest[k] for k in ("price", "time", "precision")}

        tool_cfg = {"rpc": {"url": self.url, "cookie": self.cookie}, "wallet": "oracle-ops", "bond_log": bond_log,
                    "signer_config": signer_cfg, "seqc": SEQC}
        cfg = self.write("bond.json", tool_cfg)
        tool = os.path.join(BIN, "sequentia-oracle-bond")
        bad = run(tool, "--config", self.write("bond-bad.json", dict(tool_cfg, wallet="treasury2026")),
                  "status", ok=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("refusing wallet 'treasury2026'", bad.stderr)
        ev["refuses_treasury_wallet"] = bad.stderr.strip().splitlines()[-1]
        for svc in ("compages", "seqpal-escrow", "pignus-beacon-1"):
            bad = run(tool, "--config", self.write("bond-bad.json", dict(tool_cfg, wallet=svc)), "status", ok=False)
            self.assertIn(f"refusing wallet '{svc}'", bad.stderr)
        ev["refuses_service_wallets"] = bad.stderr.strip().splitlines()[-1]
        run(tool, "--config", cfg, "post", "--amount", "1000")
        self.mine()
        again = run(tool, "--config", cfg, "post", "--amount", "1", ok=False)
        self.assertIn("top-up", again.stderr)
        run(tool, "--config", cfg, "top-up", "--amount", "250")
        self.mine()
        st = json.loads(run(tool, "--config", cfg, "status").stdout)
        b = st["bonds"][0]
        self.assertEqual(b["bonded_atoms"], 1250 * 10 ** 8)
        ev["status_after_post_and_top_up"] = {"bonded_atoms": b["bonded_atoms"], "coins": len(b["coins"])}
        k1 = [c for c in b["coins"] if c["amount"] == 1000 * 10 ** 8][0]
        k1_op = f"{k1['txid']}:{k1['vout']}"

        # -- 2. notice, an early withdrawal refused, the withdrawal ------------------
        p = run(tool, "--config", cfg, "notice", "--coin", k1_op, ok=False)
        self.assertEqual(p.returncode, 3, p.stderr)
        cmd = p.stderr.strip().splitlines()[-1].split()
        self.assertEqual(cmd[0], "sequentia-oracle-signer")
        run(os.path.join(BIN, cmd[0]), *cmd[1:])
        sent = json.loads(run(tool, "--config", cfg, "notice", "--coin", k1_op).stdout)["sent"]
        self.mine()
        ev["notice"] = sent
        bond = B.declared(B.read_log(bond_log))[0]
        u1 = [c for c in B.coins(self.root, bond) if c["state"] == B.NOTICED][0]
        self.assertEqual(u1["amount"], 1000 * 10 ** 8)
        u1_op = f"{u1['txid']}:{u1['vout']}"
        dest = recv.getnewaddress("", "bech32")
        dest_spk = recv.getaddressinfo(dest)["scriptPubKey"]
        genesis = self.root.call("getblockhash", 0, wallet=False)
        run(signer, "--config", signer_cfg, "--bond-withdraw", u1_op, "--to", dest_spk, "--genesis", genesis)
        early = run(tool, "--config", cfg, "withdraw", "--to", dest, "--coin", u1_op)
        self.assertEqual(json.loads(early.stdout)["sent"], [])
        self.assertIn("notice runs until", early.stderr)
        # The same withdrawal, built and forced into a block: consensus refuses it.
        rec = [r for r in B.read_log(bond_log) if r["kind"] == "withdraw"][-1]
        s = B.compose_moved(ops, bond, u1, "withdraw", dest_spk, bond_asset)
        s.finish(SEQC, genesis, B.withdraw_path(rec["dest"], rec["signature"]))
        raw = s.sign(ops)
        mem = self.root.call("testmempoolaccept", [raw], wallet=False)[0]
        self.assertEqual(mem["reject-reason"], "non-BIP68-final")
        try:
            self.root.call("generateblock", self.funder.getnewaddress(), [raw], wallet=False)
            self.fail("an early withdrawal was mined")
        except R.RPCError as e:
            self.assertIn("bad-txns-nonfinal", str(e))
            ev["early_withdrawal"] = {"mempool": mem["reject-reason"], "block": str(e)}
        self.advance(NOTICE + 600)
        out = json.loads(run(tool, "--config", cfg, "withdraw", "--to", dest, "--coin", u1_op).stdout)
        self.assertEqual(len(out["sent"]), 1)
        self.mine()
        got = [u for u in recv.listunspent() if u["asset"] == bond_asset]
        self.assertEqual([B.atoms(u["amount"]) for u in got], [1000 * 10 ** 8])
        ev["withdrawal"] = out["sent"][0]

        # A third coin, and notice on it: a bond in notice is still slashable.
        run(tool, "--config", cfg, "top-up", "--amount", "300")
        self.mine()
        k3 = [c for c in B.coins(self.root, bond) if c["amount"] == 300 * 10 ** 8][0]
        k3_op = f"{k3['txid']}:{k3['vout']}"
        run(signer, "--config", signer_cfg, "--bond-notice", k3_op, "--genesis", genesis)
        run(tool, "--config", cfg, "notice", "--coin", k3_op)
        self.mine()
        coins = B.coins(self.root, bond)
        self.assertEqual(sorted((c["state"], c["amount"]) for c in coins),
                         [(B.BONDED, 250 * 10 ** 8), (B.NOTICED, 300 * 10 ** 8)])

        # -- 3. the watcher -----------------------------------------------------------
        with open(os.path.join(oracle_dir, "oracle.key")) as f:
            sec = bytes.fromhex(f.read().strip())
        other = bytes(31) + b"\x07"
        t, price = honest["time"], honest["price"]

        def att(s, p, tt, quote=USDX, precision=5, beacon=A.NO_BEACON):
            a = A.AttestationV2(A.xonly_pubkey(s), A.asset_from_display(GOLD), A.asset_from_display(quote),
                                p, precision, tt, beacon)
            return a.sign(s, aux=os.urandom(32)).to_dict()
        leaked = os.path.join(self.dir, "leaked.ndjson")
        no_conflicts = [att(sec, price - 1, t + 1), att(sec, price, t, beacon=b"\x09" * 32),
                        att(sec, price - 1, t, quote=SILVR), att(sec, (price - 1) * 10, t, precision=6),
                        att(other, price, t), att(other, price - 1, t)]
        with open(leaked, "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in no_conflicts)
        pay_to = watch.getnewaddress("", "bech32")
        wcfg = self.write("watcher.json", {
            "rpc": {"url": self.url, "cookie": self.cookie}, "wallet": "watcher", "pay_to": pay_to, "seqc": SEQC,
            "state": os.path.join(self.dir, "watcher-state.json"),
            "oracles": [{"name": "oracle-1", "key": key.hex(), "logs": [log_v2, leaked], "bond_log": bond_log}]})
        watcher = os.path.join(BIN, "sequentia-oracle-watcher")
        r0 = json.loads(run(watcher, "--config", wcfg, "--once").stdout)
        self.assertEqual((r0["slashed"], r0["conflicts"]), ([], 0))
        ev["watcher_on_no_conflicts"] = {"records": len(no_conflicts), "slashed": r0["slashed"]}

        lie = att(sec, price - 1, t)
        with open(leaked, "a") as f:
            f.write(json.dumps(lie) + "\n")
        r1 = json.loads(run(watcher, "--config", wcfg, "--once").stdout)
        self.assertEqual(r1["conflicts"], 1)
        self.assertEqual(len(r1["slashed"]), 2)
        self.mine()
        tip = self.root.call("getbestblockhash", wallet=False)
        ev["slashes"] = []
        for sl in r1["slashed"]:
            txv = self.root.call("getrawtransaction", sl["txid"], True, tip, wallet=False)
            self.assertGreaterEqual(txv.get("confirmations", 0), 1)
            spent = T.Tx.parse(txv["hex"])
            amount = {f"{c['txid']}:{c['vout']}": c["amount"] for c in coins}[sl["coin"]]
            self.assertEqual(spent.vout[0].script, B.BURN_SCRIPT)
            self.assertEqual(spent.vout[0].amount, amount - amount // 2)
            self.assertEqual(spent.vout[1].script.hex(), watch.getaddressinfo(pay_to)["scriptPubKey"])
            self.assertEqual(spent.vout[1].amount + spent.vout[2].amount, amount // 2)
            self.assertEqual(spent.vout[0].asset, bond_asset)
            ev["slashes"].append({"coin": sl["coin"], "bond_atoms": amount, "txid": sl["txid"],
                                  "burned": spent.vout[0].amount, "to_presenter": spent.vout[1].amount,
                                  "fee": spent.vout[2].amount, "vsize": txv["vsize"]})
        self.assertEqual(B.coins(self.root, bond), [], "every coin of the bond is slashed")
        received = sum(B.atoms(u["amount"]) for u in watch.listunspent() if u["asset"] == bond_asset)
        self.assertEqual(received, sum(s["to_presenter"] for s in ev["slashes"]))
        ev["presenter_received_atoms"] = received
        r2 = json.loads(run(watcher, "--config", wcfg, "--once").stdout)
        self.assertEqual(r2["slashed"], [], "nothing is slashed twice")


if __name__ == "__main__":
    unittest.main()
