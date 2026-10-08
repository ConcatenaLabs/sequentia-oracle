#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Assemble, from a signer's beacon log and format-2 log, the set the
contracts harness's test o2 spends (sequentia-contracts,
`O2_SET=<file> harness/run.py o2`).

    python3 tools/o2_set.py --beacon-log beacon.log --log-v2 attestations-v2.log \\
        --market GOLD/USDX > o2-set.json

o2 puts beacon coins at the second-to-last epoch's program (B1), opens a
contract under it, spends it with the newest record of MARKET naming B1,
rotates the coins to the last epoch (B2) with the signer's own rotation
signature from the log, and then refuses the B1 record and accepts the newest
record naming B2. With a record of MARKET signed before the signer had a
beacon (`zero`), it also shows that one refused. Everything in the file is
public: the key, nonces, programs and signatures the signer published.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from sequentia_oracle import attestation as A    # noqa: E402


def read(path):
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--beacon-log", required=True)
    ap.add_argument("--log-v2", required=True)
    ap.add_argument("--market", required=True)
    a = ap.parse_args()
    records = read(a.beacon_log)
    if not records:
        sys.exit("the beacon log is empty")
    key = bytes.fromhex(records[0]["key"])
    epochs = A.beacon_epochs(key, records)
    if len(epochs) < 2:
        sys.exit("the beacon has not rotated yet; o2 needs two epochs")
    b1, b2 = epochs[-2]["program"].hex(), epochs[-1]["program"].hex()
    mine = [d for d in read(a.log_v2) if d.get("market") == a.market
            and A.AttestationV2.from_dict(d).verify(key)]
    one = [d for d in mine if d["beacon"] == b1]
    two = [d for d in mine if d["beacon"] == b2]
    zero = [d for d in mine if d["beacon"] == A.NO_BEACON.hex()]
    if not one or not two:
        sys.exit(f"{a.market} needs a record naming each of the last two beacons")
    out = {"key": key.hex(), "epochs": records[-2:], "b1": one[-1], "b2": two[-1]}
    if zero:
        out["zero"] = zero[-1]
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
