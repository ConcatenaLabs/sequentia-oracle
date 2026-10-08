# Running the signer

The signer holds one oracle key, reads a price feed, and every `interval`
seconds signs each new price in format 1, format 2 or both, appending each
record to an append-only log. It listens on nothing. A web process publishes
the logs; on the Sequentia testnet that is Pignus's `pignus-oracle` with a
`signer` section in its configuration, which reads the signer's logs and
status file and never reads the key.

```
price feed ──► sequentia-oracle-signer ──► attestations.log      (format 1)
                (holds the key)        ──► attestations-v2.log   (format 2)
                                       ──► signer-status.json
                                                 │
                                                 ▼
                                   pignus-oracle (web, no key) ──► /v1/…, /v2/…
```

## Layout

The unit file `deploy/sequentia-oracle-signer@.service` is written for this
layout, one instance per oracle key; instance `1` is the primary:

| Path | What | Who writes it |
|---|---|---|
| `/root/sequentia/sequentia-oracle` | this repository, checked out | `git` |
| `/root/sequentia/oracle-signer/1.json` | instance 1's configuration | the operator |
| `/root/sequentia/oracle-signer/1/oracle.key` | instance 1's key, mode 0600, its directory 0700 | the signer, once |
| `/root/sequentia/pignus-data/attestations.log` | format-1 records, one JSON line each | the signer |
| `/root/sequentia/pignus-data/attestations-v2.log` | format-2 records | the signer |
| `/root/sequentia/pignus-data/signer-status.json` | the last round: per market its time, price or error; the feed's state; the key | the signer |

The web process's unit makes `/root/sequentia/oracle-signer` inaccessible to
it (`InaccessiblePaths=`), so it cannot read a key even by mistake. Other
instances use `2.json`, `2/oracle.key` and their own log paths.

## Configuration

`deploy/signer.example.json` is a complete example. A key the signer does not
read is refused at start; keys that start with `_` are comments.

| Key | Default | What |
|---|---|---|
| `keyfile` | required | the secret key, 64 hex characters; its mode is checked on every start |
| `log_v1`, `log_v2`, `status` | beside the key | where the records and the status go |
| `interval` | 60 | seconds between rounds |
| `formats` | `[1, 2]` | which formats to sign. Drop 1 once no loan that expects it is open |
| `markets` | required | `BASE/QUOTE` names |
| `assets` | required for format 2 | each symbol's asset id as the node prints it, or `unit:BTC` (native bitcoin) or `unit:USD` |
| `precisions` | required | each symbol's decimal places. A wrong one signs a price wrong by a power of ten |
| `precision` | 5 | format 2's precision; format 1's `price_scale` is `10^precision` |
| `symbols` | `{}` | the ticker the feed uses for a symbol, where it differs (`{"BTC": "tBTC"}`) |
| `max_jump`, `jump_rounds` | 0.5, 3 | a price that moves by more than that fraction is signed only after it has held for that many rounds |
| `flat_rounds` | 30 (0 for `static`) | after this many rounds in which every market came back unchanged, the feed is called frozen and nothing is signed |
| `source` | required | `{"type": "http_bulk", "url": …, "max_age": 300, "feed_max_age": …}`, `{"type": "http", …}` or `{"type": "static", "prices": {…}}` |

A price is the reference price of one whole BASE unit divided by one whole
QUOTE unit, converted to atoms per atom with the two precisions and multiplied
by `10^precision`. A round prices every market from one snapshot of the feed.
An observation (the feed's own `_meta.updated`, else the time it was read)
is signed once, so a feed that stops moving produces nothing that looks
fresh. A plain-http feed on another machine is refused unless the source says
`"insecure": true`.

`tools/resolve_assets.py` reads asset ids from an asset registry's minimal
index; check what it prints before it goes into `assets`, because those ids
are what format 2 signs:

    python3 tools/resolve_assets.py --registry http://127.0.0.1:3005 \
        GOLD SILVR OILX SEQ=tSEQ EURX USDX BTC=unit:BTC

## The key

- **New oracle.** `sequentia-oracle-signer --config 1.json --create-key --once`
  makes the key (0600, in a 0700 directory) and signs one round. It refuses to
  make one when either log already holds records: a signer that has signed
  before and lost its key needs the backup, because contracts and loans pin the
  old key and a new one signs for nothing they accept. Back the key up offline
  at once.
- **An existing oracle.** Move its key file into place (`mv`, then
  `chmod 600`), and point `log_v1` at the log it already writes, so the record
  of everything it signed stays one file. The signer reads the end of its logs
  at start, so it neither signs an observation twice nor forgets the jump
  guard's last price.
- `--print-pubkey` prints the x-only key that contracts and loans pin.
- Never sign anything else with this key.

## Running it

    systemctl enable --now sequentia-oracle-signer@1
    journalctl -u sequentia-oracle-signer@1 -f

The journal says each transition once: a market that stops being signed and
why, a feed that stops answering or freezes, and their recovery. Five failed
rounds in a row exit the process for systemd to restart. A second signer on the
same logs is refused (`another signer holds …lock`).

Checks:

    cat /root/sequentia/pignus-data/signer-status.json   # last_round, per-market errors
    tail -n 2 /root/sequentia/pignus-data/attestations-v2.log

## Retiring format 1

When no open loan expects format 1, remove `1` from `formats` and restart. The
format-1 log stays where it is, as the record of what was signed.

## Proving a deployment's attestations on regtest

The contracts repository's harness test `o1` spends a set of attestations
through a Simplicity leaf and a tapscript leaf. To run it on a signer's own
output, let it sign one market three times with the price rising, then

    python3 tools/o1_set.py --log-v1 attestations.log --log-v2 attestations-v2.log \
        --market GOLD/USDX --other SILVR/USDX > o1-set.json
    O1_SET=$PWD/o1-set.json python3 <sequentia-contracts>/harness/run.py o1

Do this with a test key on a test machine; the set file holds only public
records, but a test that needs more signatures than the logs hold would need
the key.
