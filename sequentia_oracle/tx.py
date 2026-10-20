# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Sequentia transactions, explicit only: enough to build a bond spend and to
read back what a wallet signed.

The encoding is Elements': version, a flags byte that is always present (1
when a witness follows), the inputs, the outputs, the lock time, then one
witness per input (issuance proofs, script stack, peg-in stack) and one per
output (surjection and range proofs). An output's asset and value are explicit
(`0x01` and the id in internal byte order; `0x01` and eight bytes big-endian),
its nonce empty. A fee output has an empty script. A transaction with an
issuance, a peg-in or a confidential output is refused: nothing here makes
one, and a parser that guessed at one could misread the rest.
"""

import hashlib
import struct


class TxError(ValueError):
    pass


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varstr(b):
    return compact(len(b)) + bytes(b)


class Reader:
    def __init__(self, b):
        self.b, self.i = bytes(b), 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise TxError("the transaction ends early")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def compact(self):
        n = self.u8()
        if n < 0xfd:
            return n
        if n == 0xfd:
            return struct.unpack("<H", self.take(2))[0]
        if n == 0xfe:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]

    def varstr(self):
        return self.take(self.compact())

    def stack(self):
        return [self.varstr() for _ in range(self.compact())]


class TxIn:
    def __init__(self, txid, vout, sequence=0xffffffff, script_sig=b""):
        self.txid, self.vout, self.sequence, self.script_sig = txid, int(vout), int(sequence), bytes(script_sig)
        self.witness = []          # the script witness stack

    def serialize(self):
        return (bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout) + varstr(self.script_sig)
                + struct.pack("<I", self.sequence))


class TxOut:
    """An explicit output: asset id (RPC display hex), atoms, scriptPubKey."""

    def __init__(self, asset, amount, script):
        self.asset, self.amount, self.script = asset, int(amount), bytes(script)
        if not 0 <= self.amount < 1 << 64:
            raise TxError("an amount out of range")

    def serialize(self):
        return (b"\x01" + bytes.fromhex(self.asset)[::-1] + b"\x01" + struct.pack(">Q", self.amount)
                + b"\x00" + varstr(self.script))

    @property
    def is_fee(self):
        return not self.script


class Tx:
    def __init__(self, version=2, locktime=0):
        self.version, self.locktime = int(version), int(locktime)
        self.vin, self.vout = [], []

    def serialize(self, witness=True):
        has = witness and any(i.witness for i in self.vin)
        b = struct.pack("<i", self.version) + bytes([1 if has else 0])
        b += compact(len(self.vin)) + b"".join(i.serialize() for i in self.vin)
        b += compact(len(self.vout)) + b"".join(o.serialize() for o in self.vout)
        b += struct.pack("<I", self.locktime)
        if has:
            for i in self.vin:
                b += varstr(b"") + varstr(b"") + compact(len(i.witness))
                b += b"".join(varstr(x) for x in i.witness) + compact(0)
            for _ in self.vout:
                b += varstr(b"") + varstr(b"")
        return b

    def hex(self):
        return self.serialize().hex()

    def txid(self):
        return sha256d(self.serialize(witness=False))[::-1].hex()

    @classmethod
    def parse(cls, raw):
        r = Reader(bytes.fromhex(raw) if isinstance(raw, str) else raw)
        t = cls(struct.unpack("<i", r.take(4))[0])
        flags = r.u8()
        if flags not in (0, 1):
            raise TxError("unknown transaction flags")
        for _ in range(r.compact()):
            txid = r.take(32)[::-1].hex()
            n = r.u32()
            if n != 0xffffffff and n & (3 << 30):
                raise TxError("an input with an issuance or a peg-in")
            script_sig = r.varstr()
            t.vin.append(TxIn(txid, n, r.u32(), script_sig))
        for _ in range(r.compact()):
            if r.u8() != 1:
                raise TxError("a confidential asset")
            asset = r.take(32)[::-1].hex()
            if r.u8() != 1:
                raise TxError("a confidential amount")
            amount = struct.unpack(">Q", r.take(8))[0]
            if r.u8() != 0:
                raise TxError("an output with a nonce")
            t.vout.append(TxOut(asset, amount, r.varstr()))
        t.locktime = r.u32()
        if flags:
            for i in t.vin:
                if r.varstr() or r.varstr():
                    raise TxError("issuance proofs")
                i.witness = r.stack()
                if r.stack():
                    raise TxError("a peg-in witness")
            for _ in t.vout:
                if r.varstr() or r.varstr():
                    raise TxError("output proofs")
        if r.i != len(r.b):
            raise TxError("bytes after the transaction")
        return t


def txout_hex(asset, amount, script):
    """A coin's output as seqc's `utxos` takes it."""
    return TxOut(asset, amount, script).serialize().hex()
