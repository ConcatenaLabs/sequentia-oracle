# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The watcher: reads oracles' public logs, finds two attestations of one
pair, precision and time at two prices, and slashes the oracle's bond.

Each oracle it watches is a key, the places its format-2 attestations are
published (the signer's log, a web process's `/v2/log/raw`, or any other
record of them: a liquidation's witness copied out, another publisher), and
its bond log, which declares the bond's terms. A record counts only when its
signature is the key's over its message; what a record says beside its
message is ignored. Every record seen is kept (by key, pair, precision and
time, for `retain_days`), so two prices published hours apart, or by two
publishers, still meet.

On a conflict it slashes every coin of every bond the oracle declared, one
transaction each: half burned, the rest to `pay_to`, the fee paid in the
bond's asset from that half when the node takes it, else by the wallet in
`fee_asset`. A slash is checked by the bond's own rule
(`sequentia_contracts`) and run through its program by `seqc` before it is
sent.
"""

import json
import os
import sys
import time
import urllib.request

from . import attestation as A
from . import bond as B
from . import rpc as R

CONFIG_KEYS = ("rpc", "wallet", "pay_to", "seqc", "fee_asset", "feerate", "state", "interval",
               "retain_days", "oracles", "timeout")
ORACLE_KEYS = ("name", "key", "logs", "bond_log")


def say(msg):
    print(f"sequentia-oracle-watcher: {msg}", file=sys.stderr, flush=True)


def load_config(path):
    with open(path) as f:
        cfg = json.load(f)
    odd = sorted(k for k in cfg if k not in CONFIG_KEYS and not k.startswith("_"))
    if odd:
        raise SystemExit(f"{path}: unknown setting(s) {', '.join(odd)}. It takes: {', '.join(CONFIG_KEYS)}")
    for k in ("rpc", "wallet", "oracles", "state"):
        if k not in cfg:
            raise SystemExit(f"{path}: `{k}` is required")
    R.check_wallet_name(cfg["wallet"])
    for o in cfg["oracles"]:
        odd = sorted(k for k in o if k not in ORACLE_KEYS and not k.startswith("_"))
        if odd:
            raise SystemExit(f"an oracle takes {', '.join(ORACLE_KEYS)}; not {', '.join(odd)}")
        if len(bytes.fromhex(o["key"])) != 32 or not o.get("logs") or not o.get("bond_log"):
            raise SystemExit("each oracle needs its 32-byte `key`, its `logs` and its `bond_log`")
    return cfg


def fetch(source, timeout=20):
    """The records at a path or an http(s) URL: newline-delimited JSON, a JSON
    list, or an object holding `attestations` or `log`."""
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=timeout) as r:
            text = r.read().decode()
    else:
        with open(source) as f:
            text = f.read()
    text = text.strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            v = json.loads(text)
            if isinstance(v, dict):
                # An object that holds the records, or a log of one line: the
                # record itself (a bond log that declares its bond and has
                # nothing else yet is exactly that).
                v = v["attestations"] if "attestations" in v else v["log"] if "log" in v else [v]
            return [d for d in v if isinstance(d, dict)]
        except ValueError:
            pass                     # newline-delimited JSON starts with { too
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict):
                out.append(d)
    return out


def signed_by(key, d):
    """(feed, price, record) when `d` is a format-2 record that `key` signed,
    else None. Only the message and the signature are read."""
    try:
        m, s = bytes.fromhex(d["message"]), bytes.fromhex(d["signature"])
    except (KeyError, ValueError, TypeError):
        return None
    if len(m) != A.MESSAGE_LEN or m[0] != A.VERSION or m[1:33] != key or len(s) != 64:
        return None
    if not A.schnorr_verify(key, A.tagged_hash(A.TAG, m), s):
        return None
    price = int.from_bytes(m[97:105], "little")
    return B.feed_of(m), price, {"message": m.hex(), "signature": s.hex(),
                                 "time": int.from_bytes(m[106:110], "little")}


class Watcher:
    def __init__(self, cfg, node=None):
        self.cfg = cfg
        self.node = node or R.Node.from_config(cfg["rpc"], wallet=cfg["wallet"])
        self.state_path = cfg["state"]
        self.retain = float(cfg.get("retain_days", 40)) * 86400
        self.timeout = float(cfg.get("timeout", 20))
        self.state = {"seen": {}, "conflicts": [], "slashed": {}}
        if os.path.exists(self.state_path):
            with open(self.state_path) as f:
                self.state.update(json.load(f))
        self._pay_to = None

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def pay_to_script(self):
        if self._pay_to is None:
            addr = self.cfg.get("pay_to") or self.node.getnewaddress("", "bech32")
            self._pay_to = self.node.getaddressinfo(addr)["scriptPubKey"]
        return self._pay_to

    def read(self, oracle):
        """Index every record the oracle's sources hold; return the feeds with
        two prices."""
        key = bytes.fromhex(oracle["key"])
        seen = self.state["seen"].setdefault(oracle["key"], {})
        for src in oracle["logs"]:
            try:
                recs = fetch(src, self.timeout)
            except Exception as e:                       # noqa: BLE001 - reported
                say(f"{oracle.get('name', oracle['key'][:12])}: cannot read {src}: {type(e).__name__}: {e}")
                continue
            for d in recs:
                got = signed_by(key, d)
                if got is None:
                    continue
                feed, price, rec = got
                seen.setdefault(feed, {}).setdefault(str(price), rec)
        cutoff = time.time() - self.retain
        for feed in [f for f, ps in seen.items() if all(r["time"] < cutoff for r in ps.values())]:
            del seen[feed]
        return {f: ps for f, ps in seen.items() if len(ps) >= 2}

    def bonds(self, oracle):
        key = bytes.fromhex(oracle["key"])
        return B.declared(fetch(oracle["bond_log"], self.timeout), key)

    def round(self):
        slashed = []
        genesis = None
        for oracle in self.cfg["oracles"]:
            name = oracle.get("name", oracle["key"][:12])
            key = bytes.fromhex(oracle["key"])
            conflicts = self.read(oracle)
            if not conflicts:
                continue
            feed, prices = sorted(conflicts.items())[0]
            r1, r2 = [prices[p] for p in sorted(prices, key=int)[:2]]
            why = B.conflict(key, r1, r2)
            if why is not None:          # cannot happen for records indexed above
                raise B.BondError(f"{name}: the pair is not a conflict ({why})")
            entry = {"oracle": oracle["key"], "feed": feed, "records": [r1, r2]}
            if entry not in self.state["conflicts"]:
                self.state["conflicts"].append(entry)
                say(f"{name}: CONFLICT, two prices for one pair and time: {sorted(prices, key=int)[:2]}")
            if genesis is None:
                genesis = self.node.call("getblockhash", 0, wallet=False)
            for bond in self.bonds(oracle):
                for c in B.coins(self.node, bond):
                    op = f"{c['txid']}:{c['vout']}"
                    if op in self.state["slashed"]:
                        continue
                    s = B.compose_slash(self.node, bond, c, self.pay_to_script(), self.cfg.get("fee_asset"),
                                        int(self.cfg.get("feerate", B.DEFAULT_FEERATE_RFA_PER_KVB)))
                    s.finish(B.find_seqc(self.cfg.get("seqc")), genesis, B.slash_path(r1, r2))
                    txid = self.node.sendrawtransaction(s.sign(self.node))
                    self.state["slashed"][op] = txid
                    slashed.append({"oracle": oracle["key"], "coin": op, "txid": txid,
                                    "burned": s.tx.vout[0].amount, "to_presenter": s.tx.vout[1].amount,
                                    "fee": list(s.fee)})
                    say(f"{name}: slashed {op} in {txid}: {s.tx.vout[0].amount} burned, "
                        f"{s.tx.vout[1].amount} to the presenter")
        self.save()
        return slashed

    def run_forever(self):
        interval = float(self.cfg.get("interval", 60))
        while True:
            try:
                self.round()
            except Exception as e:                       # noqa: BLE001 - reported
                say(f"round failed: {type(e).__name__}: {e}")
            time.sleep(interval)
