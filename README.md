# sequentia-oracle

Signed price attestations for [Sequentia](https://github.com/ConcatenaLabs/Sequentia),
a Bitcoin sidechain for asset tokenization and disintermediated exchanges.

A contract that settles against a price, a loan liquidated below its strike,
an option, a stable asset, checks an oracle's signature over that price
itself, in a Simplicity program or a tapscript leaf, against a key it pins.
This repository defines the bytes that signature is over and runs the process
that signs them.

| Path | What |
|---|---|
| [`doc/format.md`](doc/format.md) | The attestation formats: format 2, a fixed 142-byte message that Simplicity and tapscript both check, and format 1, which Pignus loans originated against; with the reasoning for every field and what a signature can and cannot authorise |
| `sequentia_oracle/attestation.py` | The reference implementation of both formats and of BIP340, Python standard library only, in one file that other projects vendor |
| `vectors/attestations.json` | Golden vectors, written by `tools/gen_vectors.py`. The Rust reader in [`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts) reproduces them byte for byte, and its harness test `o1` spends one through a Simplicity leaf and a tapscript leaf on regtest |
| `bin/sequentia-oracle-signer`, `sequentia_oracle/signer.py`, `sequentia_oracle/feed.py` | The signer: holds the key, reads a price feed, writes both formats to append-only logs. It serves nothing |
| [`doc/runbook.md`](doc/runbook.md), `deploy/` | Configuration, the systemd unit, and how it runs beside the web process that publishes the logs |
| `tools/` | `gen_vectors.py`; `resolve_assets.py` (asset ids from a registry); `o1_set.py` (a signer's records as a set for the regtest proof) |

## Format 2 in one paragraph

    message = 0x02 || key (32) || base (32) || quote (32) || price (8, LE)
              || precision (1) || time (4, LE) || beacon (32)
    signature = BIP340(SHA256(SHA256(T) || SHA256(T) || message)),  T = "Sequentia/oracle/price"

`base` and `quote` are Sequentia asset ids in internal byte order, or the ids
of two units that are not Sequentia assets: native bitcoin (`BTC`) and the US
dollar (`USD`). The value is `price / 10^precision` quote atoms per base atom.
`beacon` is all zero until freshness through a beacon coin is specified.

## Verifying an attestation

```python
from sequentia_oracle.attestation import AttestationV2

att = AttestationV2.from_dict(record)          # refuses a malformed record
assert att.verify(pinned_key)                  # the key you trust, as bytes
assert (att.base, att.quote, att.precision) == expected
price_num, price_den = att.value()
```

## Running the signer

```sh
python3 bin/sequentia-oracle-signer --config signer.json --create-key --once   # a new oracle
python3 bin/sequentia-oracle-signer --config signer.json                       # sign every interval
python3 bin/sequentia-oracle-signer --config signer.json --print-pubkey
```

[`doc/runbook.md`](doc/runbook.md) covers the configuration, the key, the unit
file and retiring format 1.

## Tests

```sh
python3 tests/test_attestation.py   # BIP340's own vectors, the golden vectors, every refusal
python3 tests/test_signer.py        # the signer against a local feed
```

Python 3.10 or later, standard library only.

## License

MIT
