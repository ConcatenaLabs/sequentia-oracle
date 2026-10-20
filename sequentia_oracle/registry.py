# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The oracle's record in a Sequentia registry, and the key's signature on it.

A registry (sequentia-registry, "Oracle keys") lists an oracle key with the
feeds it signs, who runs it and where its attestations are published. A
version 2 record also names the oracle's beacon asset and its bond's terms:

    {
      "version": 2,
      "key": "<x-only key>",
      "feeds": [{"id": "GOLD/USDX", "description": "...", "decimals": 5}],
      "operator": {"name": "...", "domain": "..."},
      "endpoints": ["https://.../v2/log/raw"],
      "attestation_tag": "Sequentia/oracle/price",
      "beacon_asset": "<the beacon asset, as the node prints it>",
      "bond": {"template": "<sequentia/oracle-bond>", "asset": "...",
               "notice": "<NOTICE, 8 hex digits>", "notice_seconds": 2592000,
               "bonded": "<script while bonded>", "noticed": "<script in notice>",
               "log": "https://.../v2/bond/log"},
      "revoked": false
    }

The key signs BIP340 over tagged("sequentia-registry/oracle-key/v1", the
record's canonical JSON): keys sorted, no whitespace, as the registry writes
it. That tag is the registry's alone; an attestation is tagged
"Sequentia/oracle/price", a bond digest "Sequentia/oracle/bond" and a beacon
rotation "Sequentia/oracle/beacon", so the signature on a record is no
attestation, no bond move and no rotation, and none of those is a record.

What the signer signs is checked here first: a record that names this key,
and whose bond, when the signer has one, is this signer's bond as it declares
it on its bond log. The registry derives the bond's two scripts again from the
key, the asset and the notice, so a record that misstates them is refused
there too.
"""

import json

from . import attestation as A
from . import bond as B

TAG = "sequentia-registry/oracle-key/v1"
FIELDS = ("version", "key", "feeds", "operator", "endpoints", "attestation_tag", "beacon_asset", "bond",
          "revoked")
BOND_FIELDS = ("template", "asset", "notice", "notice_seconds", "bonded", "noticed", "log")


class RecordError(ValueError):
    pass


def _plain(v, where="record"):
    """Only what canonical JSON writes the same in every language: objects,
    lists, strings, booleans, null and integers. A float would be written
    differently by JavaScript, and the signature would not verify there."""
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise RecordError(f"{where}: a key that is not a string")
            _plain(x, f"{where}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _plain(x, f"{where}[{i}]")
    elif isinstance(v, bool) or v is None or isinstance(v, str):
        pass
    elif isinstance(v, int):
        if abs(v) > 2 ** 53 - 1:
            raise RecordError(f"{where}: an integer beyond 2^53, which JavaScript cannot hold exactly")
    else:
        raise RecordError(f"{where}: {type(v).__name__} is not written the same by every reader; use an "
                          "integer or a string")


def canonical(record):
    """The bytes the key signs: the registry's canonical JSON."""
    _plain(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(record):
    return A.tagged_hash(TAG, canonical(record))


def bond_terms(bond, log_url=None):
    """The bond section of a record, from the signer's bond (B.Bond)."""
    d = bond.declaration()
    out = {k: d[k] for k in ("template", "asset", "notice", "notice_seconds", "bonded", "noticed")}
    if log_url:
        out["log"] = log_url
    return out


def check(record, key, bond=None):
    """Refuse a record the signer `key` (32 bytes) with `bond` (B.Bond or
    None) must not sign. Returns nothing; raises RecordError."""
    if not isinstance(record, dict):
        raise RecordError("a record is a JSON object")
    _plain(record)
    odd = sorted(set(record) - set(FIELDS))
    if odd:
        raise RecordError(f"the record has fields a registry does not know: {', '.join(odd)}")
    if record.get("version") != 2:
        raise RecordError("this signer signs version 2 records (the beacon asset and the bond beside the key)")
    if record.get("key") != key.hex():
        raise RecordError(f"the record names the key {record.get('key')}, and this signer's is {key.hex()}: "
                          "a signer signs only its own record")
    ba = record.get("beacon_asset")
    if not isinstance(ba, str) or len(ba) != 64 or ba != ba.lower():
        raise RecordError("beacon_asset: the beacon asset as the node prints it, 64 lowercase hex digits")
    A.asset_from_display(ba)
    if record.get("attestation_tag") != A.TAG:
        raise RecordError(f"attestation_tag: the tag this key signs format-2 prices under, {A.TAG}")
    rb = record.get("bond")
    if bond is None:
        if rb is not None:
            raise RecordError("the record names a bond, and this signer has none: give it its `bond` section, or "
                              "leave the bond out of the record")
        return
    if rb is None:
        raise RecordError("this signer stands behind a bond, and the record leaves it out: a record that hides "
                          "the bond a key declares on its bond log is not one it signs")
    if not isinstance(rb, dict):
        raise RecordError("bond: an object")
    odd = sorted(set(rb) - set(BOND_FIELDS))
    if odd:
        raise RecordError(f"bond: fields a registry does not know: {', '.join(odd)}")
    want = bond_terms(bond)
    for k, v in want.items():
        if rb.get(k) != v:
            raise RecordError(f"bond.{k} is {rb.get(k)!r}; this signer's bond, as its bond log declares it, has "
                              f"{v!r}")
    if "log" in rb and not (isinstance(rb["log"], str) and rb["log"].startswith("https://")):
        raise RecordError("bond.log: an https URL where the bond log is published")


def sign(secret, record, aux=bytes(32)):
    """{record, signature} as a registry takes it."""
    sig = A.schnorr_sign(secret, record_hash(record), aux)
    if not A.schnorr_verify(A.xonly_pubkey(secret), record_hash(record), sig):
        raise RecordError("the signature does not verify")
    return {"record": record, "signature": sig.hex()}


def verify(entry):
    """Whether {record, signature} is the record's key's signature over it."""
    r = entry["record"]
    return A.schnorr_verify(bytes.fromhex(r["key"]), record_hash(r), bytes.fromhex(entry["signature"]))
