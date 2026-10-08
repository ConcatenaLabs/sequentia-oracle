# Running the signer

The signer holds one oracle key, reads a price feed, and every `interval`
seconds signs each new price in format 1, format 2 or both, appending each
record to an append-only log. With a beacon it also rotates the beacon its
format-2 records name. It listens on nothing. A web process publishes
the logs; on the Sequentia testnet that is Pignus's `pignus-oracle` with a
`signer` section in its configuration, which reads the signer's logs and
status file and never reads the key.

```
price feed ──► sequentia-oracle-signer ──► attestations.log      (format 1)
                (holds the key)        ──► attestations-v2.log   (format 2)
                                       ──► signer-status.json
                                       ──► beacon.log            (rotations)
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
| `/root/sequentia/pignus-data/signer-status.json` | the last round: per market its time, price or error; the feed's state; the key; the current beacon | the signer |
| `/root/sequentia/pignus-data/beacon.log` | one line per beacon epoch: nonce, program, rotation signature | the signer |
| `/root/sequentia/pignus-data/beacon-rotate.request` | present when someone asked for a rotation; removed once it is done | the publisher or the operator |

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
| `beacon` | none | `{"rotate_every": 3600, "log": …, "request": …}`: sign under a beacon (below). Without it, format-2 records carry a zero beacon |

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

## The beacon

With a `beacon` section, every format-2 record names the signer's current
beacon (`doc/format.md`, "The beacon"), and contracts that check freshness
accept a record only while its beacon's coins are where it says.

| `beacon` key | Default | What |
|---|---|---|
| `rotate_every` | 3600 | seconds between scheduled rotations; 0 rotates on request only |
| `log` | `beacon.log` beside `log_v2` | the beacon log; back it up with the key, though it holds no secret |
| `request` | `beacon-rotate.request` beside `log_v2` | a file whose existence asks for a rotation |

- **The first round** with a `beacon` section starts epoch 0 with a fresh
  nonce and says its program in the journal and in the status file
  (`beacon.program`).
- **Funding.** Issue a beacon asset once, with no reissuance token, and pay
  its whole supply as a few one-atom coins to `OP_1 <epoch-0 program>` in the
  issuing transaction, so no coin of it is ever anywhere else. The asset id is
  what contracts pin beside the key: publish it with the key. On the Sequentia
  testnet, Pignus's `pignus-oracle --fund-beacon` does this from its node
  wallet.
- **Rotation.** At each round the signer rotates when the epoch is
  `rotate_every` old or the request file exists: it signs the move from the
  current program to a new one, writes it to the beacon log, removes the
  request, and signs every later record (and the current observation again,
  in format 2) under the new beacon. It holds no node connection, so it does
  not move the coins itself: a publisher replays the rotation from the log.
  Pignus's `pignus-oracle` with a `beacon` section does that every round,
  paying the fee from its node wallet, and `pignus-oracle --rotate-beacon`
  writes the request file.
- **A rotation by hand:** `touch /root/sequentia/pignus-data/beacon-rotate.request`.
- The signer refuses to start when its beacon log has been edited (a broken
  chain of rotations) or is missing while its format-2 log names a beacon:
  restore it from the backup or from a publisher's copy (`/v2/beacon/log` on
  `pignus-oracle`).

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

Test `o2` proves the beacon the same way: let the signer sign a market, rotate
once (the request file), and sign again, then

    python3 tools/o2_set.py --beacon-log beacon.log --log-v2 attestations-v2.log \
        --market GOLD/USDX > o2-set.json
    O2_SET=$PWD/o2-set.json python3 <sequentia-contracts>/harness/run.py o2

It puts beacon coins at the older of the last two programs, settles a
contract on the record naming it, replays the signer's own rotation, and
shows that record refused in a block and the one naming the new beacon
accepted.
