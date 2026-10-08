#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Assemble, from a signer's logs, the attestation set the contracts harness's
test o1 spends (sequentia-contracts, `O1_SET=<file> harness/run.py o1`).

    python3 tools/o1_set.py --log-v1 attestations.log --log-v2 attestations-v2.log \
        --market GOLD/USDX --other SILVR/USDX > o1-set.json

o1 pins the key, pair and precision of `ok`, sets NOT_BEFORE to its time and
STRIKE to its price plus one, and needs, all from this signer:
  ok          a format-2 record of MARKET,
  early       an earlier one of MARKET at a price no higher (refused: too early),
  high        a later one of MARKET at a higher price (refused: not under the strike),
  other_pair  a record of OTHER (refused: another pair),
  v1          the format-1 record of ok's observation (refused: the other format).
So the signer must have signed MARKET at least three times, the middle price
above the first and below the third.
"""

import argparse
import json
import sys


def read(path):
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log-v1", required=True)
    ap.add_argument("--log-v2", required=True)
    ap.add_argument("--market", required=True)
    ap.add_argument("--other", required=True)
    a = ap.parse_args()
    v2 = read(a.log_v2)
    mine = [d for d in v2 if d.get("market") == a.market]
    other = [d for d in v2 if d.get("market") == a.other]
    if not other:
        sys.exit(f"no record of {a.other}")
    for i, ok in enumerate(mine):
        early = [d for d in mine[:i] if d["time"] < ok["time"] and d["price"] <= ok["price"]]
        high = [d for d in mine[i + 1:] if d["time"] >= ok["time"] and d["price"] > ok["price"]]
        if not early or not high:
            continue
        v1 = [d for d in read(a.log_v1) if d.get("market") == a.market
              and d["timestamp"] == ok["time"] and d["price"] == ok["price"]]
        if len(v1) != 1:
            sys.exit(f"{len(v1)} format-1 records of that observation, not 1")
        json.dump({"ok": ok, "early": early[-1], "high": high[0],
                   "other_pair": other[-1], "v1": v1[0]}, sys.stdout, indent=1)
        print()
        return
    sys.exit(f"no record of {a.market} has an earlier one at a price no higher "
             f"and a later one at a higher price")


if __name__ == "__main__":
    main()
