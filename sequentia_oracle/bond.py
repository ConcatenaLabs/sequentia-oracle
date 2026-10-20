# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The oracle bond: coins an oracle puts behind its format-2 attestations.

The covenant is sequentia-contracts' `templates/oracle_bond` (its
`docs/oracle-bond.md` is the specification), vendored in
`sequentia_contracts/` with the Python address mirror and pinned by its
`PIN.json`. Nothing here derives the bond's address or rules a conflict by
any other code.

    output   P2TR(NUMS, {bond program, data(ORACLE || BOND_ASSET || NOTICE || STATE)})
    notice   the key signs tagged("Sequentia/oracle/bond", 0x01 || genesis || txid || vout)
    withdraw the key signs tagged("Sequentia/oracle/bond", 0x02 || genesis || txid || vout || dest)
    slash    anyone, with two attestations of one pair, precision and time at two
             prices: output 2k burns at least half the coin to OP_RETURN

What this module adds: the bond's two scripts from an oracle's key, asset and
notice; the bond log, which records the bond's terms and every bond digest the
key signs; the coins at the bond's scripts on a node; and each spend built,
run through the program by `seqc` and signed by a wallet for its fee.
"""

import hashlib
import json
import os
import shutil
import subprocess
import time

from . import attestation as A
from . import tx as T
from .sequentia_contracts import sequentia_address as SA

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(HERE, "sequentia_contracts", "templates", "oracle_bond")
TAG = "Sequentia/oracle/bond"
NOTICE, WITHDRAW = 1, 2
KINDS = {"notice": NOTICE, "withdraw": WITHDRAW}
BURN_SCRIPT = bytes([0x6A])
BONDED, NOTICED = 0, 1
SEQUENCE_TIME_FLAG = 1 << 22
MAX_UNITS = 0xFFFF
SHORT_NOTICE = 7 * 86400
PATH_T = ("Either<Either<Signature, (u256, Signature)>, "
          "(u256, u256, u8, u32, (u64, u256, Signature), (u64, u256, Signature))>")
# vsize of each spend, from sequentia-contracts' harness record b1 (slash 598,
# notice 598, withdrawal 608), rounded up for a change output.
VSIZE = {"notice": 700, "withdraw": 700, "slash": 700}
RATE_SCALE = 100_000_000
DEFAULT_FEERATE_RFA_PER_KVB = 2000


class BondError(ValueError):
    pass


def sha256(b):
    return hashlib.sha256(b).digest()


# ------------------------------------------------------------- the template

def _load():
    with open(os.path.join(TEMPLATE_DIR, "descriptor.json")) as f:
        text = f.read()
    desc = SA.loads(text)
    with open(os.path.join(TEMPLATE_DIR, "oracle_bond.simf")) as f:
        source = f.read()
    leaf = desc["template"]["tree"]["branch"][0]
    if hashlib.sha256(source.encode()).hexdigest() != leaf["simplicity"]["source_sha256"]:
        raise BondError("the vendored bond program is not the one its descriptor names")
    return desc, source, leaf["simplicity"]["cmr"]


DESCRIPTOR, SOURCE, CMR = _load()
TEMPLATE_HASH = DESCRIPTOR["template_hash"]


def notice_sequence(seconds):
    """The NOTICE parameter for a notice of at least `seconds`: BIP68's time
    flag and the count of 512-second units, rounded up."""
    seconds = int(seconds)
    if seconds <= 0:
        raise BondError("a notice is a positive number of seconds")
    units = -(-seconds // 512)
    if units > MAX_UNITS:
        raise BondError(f"a notice is at most {MAX_UNITS * 512} seconds (about 388 days)")
    return SEQUENCE_TIME_FLAG | units


def notice_seconds(seq):
    seq = int(seq)
    if seq & ~(SEQUENCE_TIME_FLAG | MAX_UNITS) or not seq & SEQUENCE_TIME_FLAG:
        raise BondError(f"NOTICE {seq:08x} is not a time-based relative lock: the "
                        "withdrawal of a bond with a notice in blocks could never be made")
    return (seq & MAX_UNITS) * 512


class Bond:
    """One bond's terms: the oracle key, the asset and the notice."""

    def __init__(self, key, asset, notice_seq):
        self.key = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
        if len(self.key) != 32:
            raise BondError("the oracle key is 32 bytes, x-only")
        self.asset = str(asset).lower()          # RPC display order
        A.asset_from_display(self.asset)
        self.notice = int(notice_seq)
        notice_seconds(self.notice)
        self._derived = {}

    @classmethod
    def from_record(cls, d):
        if d.get("kind") != "bond":
            raise BondError("not a bond declaration")
        b = cls(d["key"], d["asset"], int(d["notice"], 16))
        if d.get("template") != TEMPLATE_HASH:
            raise BondError(f"a bond declared under template {d.get('template')}, not {TEMPLATE_HASH}")
        for st, name in ((BONDED, "bonded"), (NOTICED, "noticed")):
            if name in d and d[name] != b.spk(st):
                raise BondError(f"the declaration's {name} script is not the one its terms derive")
        return b

    def params(self):
        return {"ORACLE": self.key.hex(), "BOND_ASSET": A.asset_from_display(self.asset).hex(),
                "NOTICE": "%08x" % self.notice}

    def derive(self, state):
        if state not in self._derived:
            self._derived[state] = SA.derive(DESCRIPTOR, self.params(), {"STATE": "%02x" % state})
        return self._derived[state]

    def spk(self, state):
        return self.derive(state)["script_pubkey"]

    def control_block(self, state):
        return self.derive(state)["leaves"]["bond"]["control_block"]

    def address(self, state, hrp):
        return SA.segwit_v1_address(hrp, bytes.fromhex(self.spk(state))[2:])

    def declaration(self, now=None):
        return {"kind": "bond", "key": self.key.hex(), "asset": self.asset, "notice": "%08x" % self.notice,
                "notice_seconds": notice_seconds(self.notice), "template": TEMPLATE_HASH,
                "bonded": self.spk(BONDED), "noticed": self.spk(NOTICED),
                "time": int(time.time() if now is None else now)}

    def same(self, other):
        return (self.key, self.asset, self.notice) == (other.key, other.asset, other.notice)

    def witness(self, state, path):
        p = self.params()
        return {"ORACLE": {"value": "0x" + p["ORACLE"], "type": "Pubkey"},
                "BOND_ASSET": {"value": "0x" + p["BOND_ASSET"], "type": "u256"},
                "NOTICE": {"value": str(self.notice), "type": "u32"},
                "STATE": {"value": str(state), "type": "u8"},
                "PATH": {"value": path, "type": PATH_T}}


# ------------------------------------------------------- what the key signs

def digest(kind, genesis, txid, vout, dest=None):
    """The digest the key signs for one bond coin. `genesis` and `txid` as an
    RPC prints them; `dest` the SHA256 of the destination script (withdrawal
    only)."""
    if kind not in (NOTICE, WITHDRAW) or (dest is None) != (kind == NOTICE):
        raise BondError("a notice names no destination, a withdrawal one")
    return SA.oracle_bond_digest(kind, bytes.fromhex(genesis)[::-1], bytes.fromhex(txid)[::-1], int(vout),
                                 None if dest is None else bytes(dest))


def sign_record(secret, kind_name, genesis, txid, vout, to_script=None, aux=None, now=None):
    """The bond log line for one signature: what the key signed, and why."""
    kind = KINDS[kind_name]
    dest = None if to_script is None else sha256(bytes.fromhex(to_script))
    d = digest(kind, genesis, txid, vout, dest)
    sig = A.schnorr_sign(secret, d, aux if aux is not None else os.urandom(32))
    rec = {"kind": kind_name, "key": A.xonly_pubkey(secret).hex(), "genesis": genesis, "txid": txid,
           "vout": int(vout), "digest": d.hex(), "signature": sig.hex(), "time": int(time.time() if now is None else now)}
    if to_script is not None:
        rec.update({"to": to_script, "dest": dest.hex()})
    return rec


def record_ok(key, rec):
    """A notice or withdrawal record names this key and verifies under it."""
    try:
        kind = KINDS[rec["kind"]]
        dest = bytes.fromhex(rec["dest"]) if kind == WITHDRAW else None
        if dest is not None and sha256(bytes.fromhex(rec["to"])) != dest:
            return False
        d = digest(kind, rec["genesis"], rec["txid"], rec["vout"], dest)
        return (rec["key"] == bytes(key).hex() and d.hex() == rec["digest"]
                and A.schnorr_verify(bytes(key), d, bytes.fromhex(rec["signature"])))
    except (KeyError, ValueError, TypeError):
        return False


def read_log(path):
    out = []
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def declared(records, key=None):
    """Every bond the log declares, oldest first, each once."""
    out = []
    for d in records:
        if d.get("kind") == "bond":
            b = Bond.from_record(d)
            if key is not None and b.key != bytes(key):
                raise BondError("the bond log declares a bond of another key")
            if not any(b.same(x) for x in out):
                out.append(b)
    return out


# ----------------------------------------------------------------- conflicts

def raw(rec):
    """(message, signature) of a format-2 record, as bytes; no other check."""
    return bytes.fromhex(rec["message"]), bytes.fromhex(rec["signature"])


def conflict(key, r1, r2):
    """None when two format-2 records are a conflict that slashes `key`'s
    bond, else the first reason they are not (the template's rule)."""
    m1, s1 = raw(r1)
    m2, s2 = raw(r2)
    return SA.oracle_bond_conflict(bytes(key), m1, s1, m2, s2)


def feed_of(message):
    """What a conflict holds fixed: base, quote, precision, time."""
    m = bytes(message)
    return m[33:97].hex() + m[105:110].hex()


# ------------------------------------------------------------------- chain

def coins(node, bond):
    """Every coin at the bond's two scripts, unspent, from the node's UTXO set:
    dicts of txid, vout, amount (atoms), asset, state, height."""
    want = {bond.spk(BONDED): BONDED, bond.spk(NOTICED): NOTICED}
    r = node.call("scantxoutset", "start", [{"desc": "raw(%s)" % s} for s in want], wallet=False)
    out = []
    for u in r.get("unspents", []):
        out.append({"txid": u["txid"], "vout": int(u["vout"]), "amount": atoms(u["amount"]),
                    "asset": u.get("asset"), "state": want[u["scriptPubKey"]], "height": u.get("height"),
                    "script": u["scriptPubKey"]})
    return sorted(out, key=lambda c: (c["state"], c["height"] or 0, c["txid"], c["vout"]))


def atoms(amount):
    from decimal import Decimal
    return int((Decimal(str(amount)) * RATE_SCALE).to_integral_exact())


def whole(n):
    from decimal import Decimal
    return str((Decimal(int(n)) / RATE_SCALE).quantize(Decimal("0.00000001")))


def withdrawable_at(node, coin, bond):
    """The median time past from which a coin in notice may be withdrawn: the
    median time of the block before the one that holds it, plus the notice
    (BIP68). None while the coin is unconfirmed."""
    if not coin.get("height"):
        return None
    prev = node.call("getblockhash", int(coin["height"]) - 1, wallet=False)
    mtp = node.call("getblockheader", prev, wallet=False)["mediantime"]
    return int(mtp) + notice_seconds(bond.notice)


def chain_mtp(node):
    return int(node.call("getblockheader", node.call("getbestblockhash", wallet=False), wallet=False)["mediantime"])


def hrp_of(node):
    """The chain's address prefix, as the wallet's own unconfidential address
    carries it (a custom chain may set any)."""
    a = node.getnewaddress("", "bech32")
    u = node.getaddressinfo(a).get("unconfidential") or a
    return u[:u.rindex("1")]


def fee_rates(node):
    """{asset id: rate} the node accepts fees in, from getfeeexchangerates,
    whose keys are labels for labelled assets."""
    rates = node.call("getfeeexchangerates", wallet=False) or {}
    labels = node.call("dumpassetlabels", wallet=False) or {}
    out = {}
    for k, v in rates.items():
        a = labels.get(k, k)
        if len(a) == 64 and int(v) > 0:
            out[a] = int(v)
    return out


def fee_atoms(rate, vsize, feerate_kvb=DEFAULT_FEERATE_RFA_PER_KVB):
    rfa = -(-int(feerate_kvb) * int(vsize) // 1000)
    return max(1, -(-rfa * RATE_SCALE // int(rate)))


# ------------------------------------------------------------------- spends

def find_seqc(path=None):
    for c in (path, os.environ.get("SEQC"), shutil.which("seqc")):
        if c and os.path.exists(c):
            return c
    raise BondError("no seqc: build sequentia-contracts (cargo build --release --bin seqc) and "
                    "name its target/release/seqc as `seqc` in the config, or set SEQC")


def seqc(path, request):
    p = subprocess.run([path, "run"], input=json.dumps(request).encode(), capture_output=True)
    if p.returncode != 0:
        raise BondError("seqc failed: " + p.stderr.decode()[-400:])
    r = json.loads(p.stdout.decode())
    if "error" in r:
        raise BondError("seqc: " + r["error"])
    return r


class Spend:
    """A transaction whose input 0 is a bond coin, finished by seqc; any other
    input is the wallet's, which signs it for the fee."""

    def __init__(self, bond, state, coin, kind):
        self.bond, self.state, self.coin, self.kind = bond, state, coin, kind
        self.tx = T.Tx(version=2)
        self.prev = []
        self.run = {}

    def add_input(self, txid, vout, asset, amount, script, sequence=0xffffffff):
        self.tx.vin.append(T.TxIn(txid, vout, sequence))
        self.prev.append(T.txout_hex(asset, amount, bytes.fromhex(script)))

    def finish(self, seqc_path, genesis, path):
        """The program runs on this exact transaction, or nothing is sent."""
        req = {"source": SOURCE, "witness": self.bond.witness(self.state, path),
               "tx": self.tx.serialize(witness=False).hex(), "utxos": self.prev, "index": 0,
               "control_block": self.bond.control_block(self.state), "genesis": genesis, "prune": True}
        r = seqc(seqc_path, req)
        if r.get("cmr") != CMR:
            raise BondError("seqc compiled the bond program to another root")
        if not r.get("executed"):
            raise BondError("the bond program refuses this transaction: " + str(r.get("exec_error")))
        self.run = r
        self.tx.vin[0].witness = [bytes.fromhex(r["witness_hex"]), bytes.fromhex(r["program_hex"]),
                                  bytes.fromhex(CMR), bytes.fromhex(self.bond.control_block(self.state))]
        return self

    def sign(self, node):
        """The wallet signs its inputs; the bond input's witness is kept and
        nothing else may change."""
        if len(self.tx.vin) == 1:
            return self.tx.hex()
        keep = list(self.tx.vin[0].witness)
        r = node.signrawtransactionwithwallet(self.tx.hex())
        signed = T.Tx.parse(r["hex"])
        signed.vin[0].witness = keep
        if signed.serialize(witness=False) != self.tx.serialize(witness=False):
            raise BondError("the wallet changed the transaction while signing it")
        missing = [i for i, x in enumerate(signed.vin) if not x.witness]
        if missing:
            raise BondError(f"the wallet did not sign inputs {missing}")
        self.tx = signed
        return signed.hex()


def _fee_coin(node, asset, need):
    """One confirmed wallet coin of `asset` holding at least `need` atoms."""
    best = None
    for u in node.listunspent(1, 9999999, [], False, {"asset": asset}):
        if not u.get("spendable", True) or u.get("asset") != asset:
            continue
        n = atoms(u["amount"])
        if n >= need and (best is None or n < best[1]):
            best = (u, n)
    if best is None:
        raise BondError(f"the wallet holds no confirmed coin of {asset[:16]}… with {need} atoms for the fee")
    u, n = best
    return u["txid"], int(u["vout"]), n, u["scriptPubKey"]


def compose_moved(node, bond, coin, kind, to_script, fee_asset, feerate_kvb=DEFAULT_FEERATE_RFA_PER_KVB):
    """A notice (to the bond's noticed script) or a withdrawal (to `to_script`):
    the coin at input 0 into output 0, whole; a wallet coin of `fee_asset`
    pays the fee, its change at output 1."""
    rates = fee_rates(node)
    if fee_asset not in rates:
        raise BondError(f"this node takes no fee in {fee_asset[:16]}…; name an accepted fee asset. "
                        "Nothing falls back to another asset")
    fee = fee_atoms(rates[fee_asset], VSIZE[kind], feerate_kvb)
    state = BONDED if kind == "notice" else NOTICED
    s = Spend(bond, state, coin, kind)
    seq = bond.notice if kind == "withdraw" else 0xffffffff
    s.add_input(coin["txid"], coin["vout"], bond.asset, coin["amount"], coin["script"], seq)
    ftxid, fvout, famount, fspk = _fee_coin(node, fee_asset, fee + 1)
    s.add_input(ftxid, fvout, fee_asset, famount, fspk, 0xfffffffe)
    change = node.getrawchangeaddress()
    change_spk = node.getaddressinfo(change)["scriptPubKey"]
    s.tx.vout = [T.TxOut(bond.asset, coin["amount"], bytes.fromhex(to_script)),
                 T.TxOut(fee_asset, famount - fee, bytes.fromhex(change_spk)),
                 T.TxOut(fee_asset, fee, b"")]
    s.fee = (fee_asset, fee)
    return s


def compose_slash(node, bond, coin, pay_to_script, fee_asset=None, feerate_kvb=DEFAULT_FEERATE_RFA_PER_KVB):
    """The slash of one coin: output 0 burns half the coin, rounded up, to
    OP_RETURN; the rest to the presenter at output 1. The fee is paid in the
    bond's asset out of the presenter's half when the node takes it, else by a
    wallet coin of `fee_asset`."""
    c = coin["amount"]
    burn = SA.oracle_bond_burn_min(c)
    rates = fee_rates(node)
    s = Spend(bond, coin["state"], coin, "slash")
    s.add_input(coin["txid"], coin["vout"], bond.asset, c, coin["script"])
    if bond.asset in rates:
        fee = fee_atoms(rates[bond.asset], VSIZE["slash"], feerate_kvb)
        if c - burn <= fee:
            raise BondError(f"the coin's unburned half ({c - burn} atoms) does not pay the fee ({fee})")
        s.tx.vout = [T.TxOut(bond.asset, burn, BURN_SCRIPT),
                     T.TxOut(bond.asset, c - burn - fee, bytes.fromhex(pay_to_script)),
                     T.TxOut(bond.asset, fee, b"")]
        s.fee = (bond.asset, fee)
        return s
    if not fee_asset or fee_asset not in rates:
        raise BondError(f"this node takes no fee in the bond's asset {bond.asset[:16]}…; name a "
                        "`fee_asset` it takes, held by the wallet")
    fee = fee_atoms(rates[fee_asset], VSIZE["slash"], feerate_kvb)
    ftxid, fvout, famount, fspk = _fee_coin(node, fee_asset, fee + 1)
    s.add_input(ftxid, fvout, fee_asset, famount, fspk, 0xffffffff)
    change_spk = node.getaddressinfo(node.getrawchangeaddress())["scriptPubKey"]
    s.tx.vout = [T.TxOut(bond.asset, burn, BURN_SCRIPT),
                 T.TxOut(bond.asset, c - burn, bytes.fromhex(pay_to_script)),
                 T.TxOut(fee_asset, famount - fee, bytes.fromhex(change_spk)),
                 T.TxOut(fee_asset, fee, b"")]
    s.fee = (fee_asset, fee)
    return s


def notice_path(sig_hex):
    return "Left(Left(0x%s))" % sig_hex


def withdraw_path(dest_hex, sig_hex):
    return "Left(Right((0x%s, 0x%s)))" % (dest_hex, sig_hex)


def slash_path(r1, r2):
    """The slash witness for two conflicting records."""
    m1, s1 = raw(r1)
    m2, s2 = raw(r2)
    price = lambda m: int.from_bytes(m[97:105], "little")
    return "Right((0x%s, 0x%s, %d, %d, (%d, 0x%s, 0x%s), (%d, 0x%s, 0x%s)))" % (
        m1[33:65].hex(), m1[65:97].hex(), m1[105], int.from_bytes(m1[106:110], "little"),
        price(m1), m1[110:142].hex(), s1.hex(), price(m2), m2[110:142].hex(), s2.hex())
