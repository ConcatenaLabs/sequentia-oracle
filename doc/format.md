# Price attestation formats

A price attestation is a signed statement by an oracle: "one atom of BASE was
worth this many atoms of QUOTE at this time". A contract on Sequentia that
settles against a price checks the signature itself, in a Simplicity program or
in a tapscript leaf, against the oracle key it pins. This document defines the
bytes, and why each is there.

There are two formats. **Format 2** is the one to build on: a Simplicity
program and a tapscript leaf can both check it. **Format 1** is the format
Pignus loans were originated against; the signer publishes it beside format 2,
for the same observations, for as long as loans that expect it are open.

The reference implementation is `sequentia_oracle/attestation.py` (Python,
standard library only). `vectors/attestations.json` holds the golden vectors,
which the Rust reader in
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
(`crates/sequentia-contracts/src/attestation.rs`) reproduces byte for byte, and
which a Simplicity program and a tapscript leaf accept on a regtest chain
(that repository's harness tests `o1`, and `o2` for the beacon).

## Format 2

### The message

A fixed-width message of 142 bytes:

| Offset | Bytes | Field | Encoding |
|---|---|---|---|
| 0 | 1 | `version` | `0x02` |
| 1 | 32 | `key` | the signer's x-only public key |
| 33 | 32 | `base` | what is priced: an asset id, or a unit id |
| 65 | 32 | `quote` | what it is priced in: an asset id, or a unit id |
| 97 | 8 | `price` | unsigned integer, little-endian, `1 ≤ price < 2^63` |
| 105 | 1 | `precision` | unsigned integer, `0 ≤ precision ≤ 18` |
| 106 | 4 | `time` | Unix seconds, unsigned, little-endian |
| 110 | 32 | `beacon` | the program of the signer's beacon script, or 32 zero bytes |

The value attested is

    price / 10^precision   atoms of `quote` per atom of `base`

### The signature

    digest    = SHA256(SHA256(TAG) || SHA256(TAG) || message)
    TAG       = "Sequentia/oracle/price"
    signature = BIP340(secret, digest)                    (64 bytes)

`SHA256(TAG)` is `c04934780078514d7ab2e52cded2406ac154a043874d7121dadd61942b2ca91c`.
The signature is a plain BIP340 signature over a 32-byte message, so both
`jet::bip_0340_verify` in Simplicity and `OP_CHECKSIGFROMSTACK` in tapscript
check it.

### Ids of what is priced

- **A Sequentia asset** is named by its asset id in **internal byte order**:
  the 32 bytes as a transaction carries them and as `jet::current_asset` or
  `OP_INSPECTINPUTASSET` returns them, which is the reverse of the hex an RPC
  prints. A contract can therefore compare a signed `base` with the asset of
  the coin it holds, without a byte reversal.
- **A unit that is not a Sequentia asset** is named by
  `SHA256(SHA256(UNIT_TAG) || SHA256(UNIT_TAG) || name)`, with
  `UNIT_TAG = "Sequentia/oracle/unit"`. Two units are defined:

  | Name | What | One atom is | Id |
  |---|---|---|---|
  | `BTC` | native bitcoin on the parent chain | one satoshi | `1ff5d76e833868fbf9132574c24448f043834d61c226ff64fc71e022b80909b4` |
  | `USD` | the US dollar | 1e-8 USD, the fee market's reference atom | `2c0b6e4359e7dd3aac33ce8b5a30153a9b31a71dea8037f149bb57a88ef2e367` |

### Why each field is there

- **`version`, first.** A reader refuses any version it does not know before
  it reads anything else, and a later format can change every other byte. It is
  also inside the signed bytes, so a signature over one version cannot be
  presented as another.
- **`key`.** BIP340 already binds a signature to its key; the key is in the
  message for the readers, not for the curve. A record names its signer, so a
  published log, a pair of contradictory attestations (one key, one pair, one
  time, two prices) and a threshold set's slots can be attributed without
  trying every key. It is the full 32-byte key rather than a shorter id: a
  shorter id is either computed from the key (a second hash in every contract)
  or carried as a second constant that can disagree with the key it stands
  for. A contract passes the one key it pins to both places.
- **`base` and `quote` as ids, not a market name.** Format 1 hashed a market
  name ("GOLD/USDX"), which a script cannot relate to anything it can read. An
  asset id is what a covenant reads from its own coin and its outputs, so a
  contract can require that the price it settles on is a price of the asset it
  holds. Native bitcoin is not a Sequentia asset and has no asset id; it is
  named as a unit, so a price of real BTC is attested as itself and never as a
  token standing for it.
- **`price` per atom, with a signed `precision`.** Quoting atoms per atom keeps
  a contract ignorant of either asset's decimal places: a covenant multiplies
  an amount in atoms by the price and divides by `10^precision`, both integers.
  The precision is signed because format 1 did not sign its scale: an
  attestation at a scale ten times smaller was a valid signature over a number
  that meant something else, and every consumer had to compare the scale out
  of band. Here a contract pins it, and an attestation at another precision
  fails the signature check. The price is below `2^63` so that tapscript's
  signed 64-bit opcodes read it as positive, and above zero because a zero
  price would let a covenant divide by it or seize everything for nothing.
  `10^18` is the largest power of ten below `2^63`.
- **`time` in 32 bits.** The only clocks a script can compare with are the
  transaction's lock time (`OP_CHECKLOCKTIMEVERIFY`, `jet::check_lock_time`),
  which is 32 bits, and constants. A 32-bit time fits both directly. It lasts
  until 2106, as the lock time does.
- **Little-endian integers.** Tapscript's 64-bit arithmetic on this chain reads
  8-byte little-endian operands, so a leaf can compare the price it puts into
  the message with no conversion, and `OP_LE32TOLE64` widens the time. A
  SimplicityHL integer is big-endian; the helper reverses the bytes, which
  costs only combinators.
- **`beacon`.** No script can read the current time, so nothing can require
  that an attestation is recent: an old attestation from a dip could be
  replayed later. The beacon binds each attestation to coins the signer moves
  when it rotates, so a contract can require that the beacon it names is still
  where it says. "The beacon" below defines it. **All zero means no beacon**:
  the attestation makes no claim of freshness, and a contract that checks the
  beacon refuses it.
- **A tagged hash, signed as 32 bytes.** `jet::bip_0340_verify` takes a 32-byte
  message, so format 1's 48 bytes cannot be checked in Simplicity at all. The
  tag separates this signature from everything else the same key could sign
  (below). The message is 142 bytes plus the 64-byte tag prefix, four SHA-256
  blocks.
- **Fixed width.** Every field has one width, so a message has exactly one
  parse. A tapscript leaf that assembles the message with `OP_CAT` from
  witness values must enforce those widths itself (the 64-bit comparison takes
  only 8 bytes, `OP_LE32TOLE64` only 4); otherwise a 7-byte price and a 5-byte
  time could shift bytes between fields.

### What a signature means, and what else it could authorise

An oracle's format-2 signature says one thing: this key attests this price of
this pair at this time, under this beacon. It names no coin, no contract and
no chain, on purpose: a price is a public fact, and every contract that pins
the same key, pair, precision and beacon may use the same attestation. That is
why a contract must also bind *who* acts and *on which coin* with a signature
of its own (the owner's `sig_all_hash` in the harness contract), and why the
attestation never stands in for one.

- **Another coin or contract:** accepted by design, as above.
- **Another pair, precision, beacon or key:** refused; each is in the signed
  bytes, and the contract supplies its own pinned values (or, for the beacon,
  the program of the coin it spends) when it rebuilds them.
- **Another time:** the time is signed, but "too old" cannot be checked in a
  script. A contract checks "not before" against a constant, and checks the
  beacon for "not since replaced".
- **Another chain:** an asset id is chain-specific, so an attestation of
  Sequentia assets means nothing elsewhere. A pair of two units (BTC in USD) is
  the same fact on every chain and is valid wherever its key is trusted.
- **Another format:** a format-1 signature is over 48 raw bytes and a format-2
  signature over a 32-byte digest. BIP340's challenge hashes the message after
  the nonce and the key, so messages of different lengths never share a
  challenge, and neither signature verifies as the other (tested in both
  directions, and refused in a block by both leaves in `o1`).
- **Something else the key signs:** the oracle key also signs its beacon
  rotations, over a digest tagged `Sequentia/oracle/beacon` (below), and
  co-signs Pignus's native-bitcoin seizures, as a BIP340 signature over a
  taproot signature hash. That hash is tagged `TapSighash`; a Simplicity
  `sig_all_hash` hashes the chain's genesis hash twice where a tag hash would
  go, over 132 bytes; a format-2 digest is tagged `Sequentia/oracle/price`,
  over 206; a rotation digest is tagged `Sequentia/oracle/beacon`, over 128. Distinct
  prefixes give disjoint digests, so no attestation is a transaction signature
  and no transaction signature is an attestation. That holds only while the signer computes
  every 32 bytes it signs: a key that signs a 32-byte value it was handed
  cannot tell a transaction hash from an attestation digest, and would sign a
  price it never observed. So the key signs nothing it did not build itself:
  no handed-over hashes, no untagged messages, and nothing as a wallet key.

### The JSON form

A record, as the signer logs it and a web process serves it:

```json
{"version": 2,
 "message": "02…",
 "signature": "…",
 "key": "…", "base": "…", "quote": "…", "price": 300000000,
 "precision": 5, "time": 1790000000, "beacon": "…",
 "market": "GOLD/USDX"}
```

`message` and `signature` are what a reader checks. The decoded fields beside
them are for people and must agree with the message: a reader refuses a record
whose fields say something its message does not. `market` is a label and is
not signed.

### Reading a record

1. Refuse a message that is not 142 bytes or whose first byte is not `0x02`.
2. Refuse `price` outside `1..2^63-1`, `precision` above 18, and `base` equal
   to `quote`.
3. Require that `key` is the key you trust (the one your contract or loan
   pins), then verify the BIP340 signature over the digest under it.
4. Compare `base`, `quote` and `precision` with the ones you expect before
   computing with `price`.
5. For a fresh price, require a non-zero `beacon` that holds a coin of the
   oracle's beacon asset now ("The beacon", "Checking a beacon off chain").

`AttestationV2.decode`, `.from_dict` and `.verify(key)` do 1 to 3.

## The beacon

A price attestation is a public fact with a time on it, and a script cannot
read the current time, so a contract cannot refuse an attestation for being
old. The beacon makes "old" something a contract can see on chain: the signer
keeps coins of a **beacon asset** at a **beacon script**, every attestation
names that script, and when the signer **rotates** it moves every beacon coin
to a new script. From that moment an attestation naming the old script has no
coin to point at, and a contract that requires one refuses it.

### The rule

- The `beacon` field is the 32-byte witness program of the signer's current
  beacon script: the output script is `OP_1 <beacon>`.
- A contract that checks freshness pins the oracle's key, the pair, the
  precision and the oracle's **beacon asset** (not one beacon: it must keep
  accepting the oracle's attestations across rotations). Its spending
  transaction must spend, at an input the witness names, an explicit coin of
  the beacon asset whose output script is `OP_1 <beacon>`, where `beacon` is
  the one in the signed message.
- The signer rotates on a schedule and on demand. A rotation is durable in the
  signer's beacon log before anything is signed under the new beacon, and from
  then on the signer signs only the new one.
- **A zero beacon** names no script that can hold the beacon asset, so a
  contract that checks the beacon refuses it. A signer without a beacon signs
  zero; a signer with one never does. A contract that does not check
  freshness may still pin a zero beacon, and then accepts only attestations
  from a signer without one.

An attestation therefore verifies, in a contract that checks the beacon, from
the moment its beacon's coins exist until the moment they are moved. A
rotation is the signer saying "every price I signed before this is stale";
how stale an accepted attestation can be is bounded by the rotation interval
plus the time a rotation takes to confirm.

### The beacon script

One epoch's beacon script is a taproot output with the NUMS internal key
`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (BIP341's
point with no known discrete logarithm: no key path) and two tapscript leaves
(leaf version `0xc4`, Elements tagged hashes `TapLeaf/elements`,
`TapBranch/elements`, `TapTweak/elements`):

| Leaf | Who | What it requires, for the coin at input `k` |
|---|---|---|
| recreate | anyone | output `2k` has the same output script, the same asset and the same amount. Using the beacon leaves it where it was |
| rotate | the oracle key | output `2k` is `OP_1 <to>` with the same asset and amount, and the witness carries the key's BIP340 signature over `SHA256(SHA256(T) ‖ SHA256(T) ‖ from ‖ to)`, `T = "Sequentia/oracle/beacon"`, where `from` is the coin's own program and `to` is in the witness |

```
recreate:  PUSHCURRENTINPUTINDEX INSPECTINPUTSCRIPTPUBKEY
           PUSHCURRENTINPUTINDEX DUP ADD INSPECTOUTPUTSCRIPTPUBKEY ROT EQUALVERIFY EQUALVERIFY
           (the same for INSPECTINPUTASSET/INSPECTOUTPUTASSET and INSPECTINPUTVALUE/INSPECTOUTPUTVALUE)
           1

rotate:    <nonce> DROP
           PUSHCURRENTINPUTINDEX DUP ADD INSPECTOUTPUTSCRIPTPUBKEY 1 EQUALVERIFY OVER EQUALVERIFY
           (asset and amount as in recreate)
           PUSHCURRENTINPUTINDEX INSPECTINPUTSCRIPTPUBKEY DROP SWAP CAT
           <SHA256(T) ‖ SHA256(T)> SWAP CAT SHA256 <key> CHECKSIGFROMSTACK
           witness: <signature> <to>
```

The `nonce` is 32 random bytes the signer draws for each epoch. Nothing reads
it; it is what makes each epoch's program new, so a rotation never returns to
a script that held coins before. `sequentia_oracle/attestation.py`
(`BeaconScript`, `rotation_digest`, `beacon_epochs`) is the reference, and
the vectors carry two epochs of test key A's beacon with every leaf, control
block, program and the rotation between them.

Why each part is there:

- **A beacon asset, not any coin at the script.** Anyone can pay any coin to
  an old script; only the beacon asset cannot get there. The signer issues it
  once with no reissuance token and pays the whole supply to the epoch-0
  script, so every coin of it is at the current script or on its way there by
  a rotation, and no other holder exists. A contract pins the asset and so
  needs no constant that changes at a rotation.
- **Anyone can use it.** A liquidation or a settlement is taken by whoever
  acts, not by the oracle, so the coin it must spend cannot need the oracle's
  signature. The recreate leaf lets every contract spend a beacon coin and
  hand it back unchanged; several coins let several contracts settle in one
  block.
- **Output `2k` for input `k`.** One rule binds each beacon input to its own
  output, so two beacon coins can never be satisfied by one recreated output
  and the other taken; it is the same rule other covenants here use, so a
  contract at input 0 keeps outputs 0 and 1 and a beacon at input 1 takes
  output 2.
- **The rotation signs `from` and `to`, nothing else.** It moves exactly one
  epoch's coins to exactly one new script. The coin's own program is read by
  the script, so the signature cannot move another epoch's coins, and it is
  not bound to an outpoint, so a coin someone recreated a moment ago is still
  moved by it. Anyone holding the signature can submit the rotation; it can
  only do what the oracle signed. The amount and asset are kept, so it moves
  nothing out.
- **A program, not an outpoint.** An outpoint changes every time a contract
  uses a beacon coin (the recreated coin is a new output), so an attestation
  naming an outpoint would die at its first use, and anyone could kill every
  attestation by spending the beacon and recreating it. A program is stable
  under use and changes only when the oracle's key moves it. It is also what
  both checks read without a conversion: tapscript's
  `OP_INSPECTINPUTSCRIPTPUBKEY` returns the program itself, and a Simplicity
  program hashes `0x5120 ‖ beacon` once and compares it with
  `jet::input_script_hash`.
- **No key path.** With one, the key could move the coins anywhere in one
  signature, including back to an old script.

The beacon coins are explicit (transparent), as a covenant that reads
amounts needs. One atom per coin is enough: a node that does not price the
beacon asset as a fee asset applies no dust limit to it.

### What a rotation signature means

It says one thing: "this key's beacon moves from program `from` to program
`to`". It cannot authorise:

- **Another epoch or a return.** The leaf puts the coin's own program in the
  digest, so the signature moves only coins at `from`; a rotation from `to`
  back to `from` is another digest, which the signer never signs (its log
  refuses a program used before).
- **Another destination or a theft.** The leaf checks the output against `to`
  and keeps asset and amount.
- **A price.** A rotation digest is tagged `Sequentia/oracle/beacon` and an
  attestation digest `Sequentia/oracle/price`; neither signature verifies as
  the other (tested both ways).

### The beacon log

The signer appends one JSON line per epoch:

```json
{"epoch":1,"from":"…","key":"…","nonce":"…","program":"…","signature":"…","time":1790000030}
```

Epoch 0 has `from` and `signature` null. `beacon_epochs(key, records)`
checks a log: consecutive epochs, every program the one its nonce derives,
every `from` the previous program, every signature this key's, no program
twice. The log is public (it holds no secret) and is what a publisher
replays rotations from: the nonce gives the leaves, and the leaves give the
control block that spends a coin.

### Checking a beacon off chain

A reader with a node (a web process before it serves an attestation, a
lending book before it computes with one) holds an attestation's beacon live
when its node shows an unspent coin of the oracle's beacon asset at output
script `OP_1 <beacon>`, in a block or in the mempool. That is the condition a
contract checks when the spend is made, so the reader agrees with the chain
rather than with the signer's log. A rotation that is signed but not yet
broadcast leaves the newest attestations without a coin and the older ones
still live: a reader shows both facts.

## Format 1

The format Pignus loans originated so far expect, defined by the covenant
builder in the node repository (`test/functional/pignus_covenant.py`,
`attestation_message`):

    message   = feed_id (32) || timestamp (8, LE) || price (8, LE)
    feed_id   = SHA256(SHA256("Pignus/feed") || SHA256("Pignus/feed") || market)
    signature = BIP340(secret, message)                    (a 48-byte message)

`market` is canonical: upper case, one slash, no spaces (`GOLD/USDX`). `price`
is debt-asset atoms per collateral-asset atom times the loan's `price_scale`,
which is **not** signed; a reader compares it with the loan's own. Only
`OP_CHECKSIGFROMSTACK`, which takes a message of any length, can check it.

Its JSON form is the line Pignus logs:

```json
{"feed_id":"…","market":"GOLD/USDX","price":300000000,"price_scale":100000,"signature":"…","timestamp":1790000000}
```

The signer writes both formats for one observation with the same time and the
same integer price: format 1's `price_scale` is `10^precision` of format 2.

## Vectors

`vectors/attestations.json`, written by `tools/gen_vectors.py` and never by
hand, holds:

- two test keys, A and B, with their secrets (they must never sign anything
  real);
- seven format-2 attestations: GOLD in USDX by A, the same oracle and time for
  another pair, the same fields by B, native bitcoin in US dollars (two units,
  precision 0), the first observation under A's beacon in epoch 0, every field
  at its largest value, and the next observation under A's beacon in epoch 1;
  each with its message, digest and signature (BIP340 with all-zero auxiliary
  randomness, so every language derives the same bytes);
- A's beacon in epochs 0 and 1: each epoch's nonce, leaves, control blocks,
  merkle root and program, the rotation between them (digest and signature),
  and the two lines of the beacon log that record them;
- the format-1 attestation of the first observation;
- nine messages a reader must refuse, each with the reason.
