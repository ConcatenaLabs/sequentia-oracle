#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Print the `assets` map of a signer config, resolved from an asset registry.

    python3 tools/resolve_assets.py --registry http://127.0.0.1:3005 \
        GOLD SILVR OILX SEQ=tSEQ EURX USDX BTC=unit:BTC

Each argument is a market symbol, optionally `SYMBOL=TICKER` when the registry
lists it under another ticker, or `SYMBOL=unit:BTC` / `SYMBOL=unit:USD` for a
unit that is not a Sequentia asset. The registry's minimal index
(`/index.minimal.json`, asset id -> [.., ticker, ..]) is read once; a ticker
that is missing or listed twice is an error, never a guess. Review the output
before it goes into a config: these ids are what the signer will sign.
"""

import argparse
import json
import sys
import urllib.request


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--registry", required=True)
    ap.add_argument("symbols", nargs="+")
    a = ap.parse_args()
    with urllib.request.urlopen(a.registry.rstrip("/") + "/index.minimal.json", timeout=10) as r:
        idx = json.loads(r.read().decode())
    by = {}
    for asset, row in idx.items():
        if len(asset) == 64 and isinstance(row, list) and len(row) > 1 and row[1]:
            by.setdefault(str(row[1]).upper(), []).append(asset)
    out, bad = {}, []
    for arg in a.symbols:
        sym, _, ticker = arg.partition("=")
        ticker = ticker or sym
        if ticker.startswith("unit:"):
            out[sym.upper()] = ticker
            continue
        hits = by.get(ticker.upper(), [])
        if len(hits) != 1:
            bad.append(f"{sym}: the registry lists {len(hits)} assets with ticker {ticker}")
            continue
        out[sym.upper()] = hits[0]
    if bad:
        sys.exit("\n".join(bad))
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
