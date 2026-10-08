# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The signer: holds the oracle key, reads a price feed, writes attestations.

It serves nothing. Each round it prices every configured market from one
snapshot of the feed, signs each new price once in every configured format,
and appends the records to append-only logs. A separate web process (Pignus's
`pignus-oracle` in its external-signer mode, or any other) publishes those
logs and never sees the key.

What it will not sign is most of this file: a price nobody observed (a feed
that answers with the same board for `flat_rounds` rounds, or a snapshot older
than the source allows), a price that jumped further than `max_jump` until it
has held for `jump_rounds` rounds, a market whose assets lack a decimal count,
and the same observation twice.
"""

import fcntl
import json
import math
import os
import stat
import sys
import time

from . import attestation as A
from . import feed as F

# Every top-level key a signer config may have. Anything else is refused: a
# setting that goes nowhere is one the operator believes is protecting them.
CONFIG_KEYS = ("keyfile", "log_v1", "log_v2", "status", "interval", "formats",
               "markets", "assets", "precisions", "symbols", "precision",
               "max_jump", "jump_rounds", "flat_rounds", "source")

SOURCE_KEYS = {
    "static": {"type", "prices"},
    "http": {"type", "url", "timeout", "field", "feed_max_age", "max_age",
             "insecure"},
    "http_bulk": {"type", "url", "timeout", "field", "max_age",
                  "feed_max_age", "insecure"},
}

# How much of an existing log is read back at start to learn the last price
# signed for each market.
TAIL_BYTES = 512 * 1024


class ConfigError(SystemExit):
    pass


def say(msg):
    print(f"sequentia-oracle-signer: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ the key

def read_key(path):
    """The secret key from a file, its mode and contents checked on every read."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise ConfigError(
            f"{path} is mode {mode:04o}: the oracle key is readable by other "
            f"users. chmod 600 it and, since it may already have leaked, "
            f"consider rotating to a new key")
    with open(path) as f:
        raw = f.read().strip()
    try:
        return A.check_secret(bytes.fromhex(raw))
    except ValueError as e:
        raise ConfigError(
            f"{path} does not hold a usable key ({e}). Restore the backup of "
            f"the key this oracle's attestations are trusted under; a new key "
            f"signs for nothing that pins the old one.") from None


def make_key(path):
    sec = os.urandom(32)
    while True:
        try:
            A.check_secret(sec)
            break
        except ValueError:
            sec = os.urandom(32)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(sec.hex() + "\n")
    say(f"CREATED a new key at {path}; back it up now. Every contract that "
        f"pins it can only ever be settled by this file.")
    return sec


# --------------------------------------------------------------- the config

def load_config(path):
    with open(path) as f:
        cfg = json.load(f)
    odd = sorted(k for k in cfg if k not in CONFIG_KEYS and not k.startswith("_"))
    if odd:
        raise ConfigError(f"{path}: unknown setting(s) {', '.join(odd)}. A signer "
                          f"config takes: {', '.join(CONFIG_KEYS)}")
    for k in ("keyfile", "markets", "source"):
        if k not in cfg:
            raise ConfigError(f"{path}: `{k}` is required")
    return cfg


def build_source(cfg):
    s = cfg.get("source", {})
    kind = s.get("type", "static")
    known = SOURCE_KEYS.get(kind)
    if known is None:
        raise ConfigError(f"unknown price source type: {kind!r}")
    odd = sorted(k for k in s if k not in known and not k.startswith("_"))
    if odd:
        raise ConfigError(f"the {kind!r} price source does not understand "
                          f"{', '.join(odd)}. It takes: {', '.join(sorted(known))}")
    if kind == "static":
        return F.StaticPriceSource(s.get("prices", {}))
    try:
        F.check_feed_url(s["url"], insecure=bool(s.get("insecure", False)))
    except SystemExit as e:
        raise ConfigError(str(e)) from None
    if kind == "http":
        return F.HttpPriceSource(s["url"], timeout=float(s.get("timeout", 5)),
                                 field=s.get("field", "price"),
                                 feed_max_age=float(s.get("feed_max_age", 0)),
                                 max_age=float(s.get("max_age", 0)))
    return F.BulkHttpPriceSource(s["url"], timeout=float(s.get("timeout", 8)),
                                 field=s.get("field", "price"),
                                 max_age=float(s.get("max_age", 300)),
                                 feed_max_age=float(s.get("feed_max_age", 0)))


def canonical(market):
    return "/".join(p.strip().upper() for p in str(market).split("/"))


def asset_ref(spec, symbol):
    """What a format-2 message names an asset by: a Sequentia asset id in the
    order a script reads it, or a unit id for "unit:BTC" or "unit:USD"."""
    spec = str(spec)
    if spec.startswith("unit:"):
        return A.unit_id(spec[len("unit:"):])
    try:
        return A.asset_from_display(spec)
    except ValueError:
        raise ConfigError(f"assets.{symbol} is {spec!r}: give an asset id as the "
                          f"node prints it (64 hex characters), or unit:BTC or "
                          f"unit:USD") from None


# --------------------------------------------------------------------- logs

def append_line(path, line):
    """Append one record and make it durable before it counts as signed: an
    attestation published but not on record is what the log exists to rule
    out, so a log that cannot be written is an outage."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def read_tail(path):
    """The records at the end of a log, oldest first."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    out = []
    with open(path, "rb") as f:
        if size > TAIL_BYTES:
            f.seek(size - TAIL_BYTES)
            f.readline()
        for line in f:
            try:
                d = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(d, dict):
                out.append(d)
    return out


def write_atomic(path, data):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


# ------------------------------------------------------------------- signer

class Signer:
    def __init__(self, cfg, create_key=False):
        self.cfg = cfg
        self.markets = [canonical(m) for m in cfg["markets"]]
        if len(set(self.markets)) != len(self.markets):
            raise ConfigError("a market is listed twice")
        self.formats = sorted({int(f) for f in cfg.get("formats", [1, 2])})
        if not self.formats or any(f not in (1, 2) for f in self.formats):
            raise ConfigError("`formats` lists 1, 2 or both")
        self.precision = int(cfg.get("precision", 5))
        if not 0 <= self.precision <= A.MAX_PRECISION:
            raise ConfigError(f"precision must be 0..{A.MAX_PRECISION}")
        self.price_scale = 10 ** self.precision
        self.precisions = {k.upper(): int(v) for k, v in cfg.get("precisions", {}).items()}
        need = sorted({s for m in self.markets for s in m.split("/")})
        missing = [s for s in need if s not in self.precisions]
        if missing:
            raise ConfigError(
                "precisions missing for " + ", ".join(missing) + ": every asset "
                "named in `markets` needs its decimal count, because a wrong one "
                "signs a price wrong by a power of ten and the signature over it "
                "is perfectly good.")
        self.refs = {}
        if 2 in self.formats:
            assets = {k.upper(): v for k, v in cfg.get("assets", {}).items()}
            missing = [s for s in need if s not in assets]
            if missing:
                raise ConfigError(
                    "assets missing for " + ", ".join(missing) + ": format 2 "
                    "names each side of a pair by its asset id (or unit:BTC, "
                    "unit:USD), so every asset in `markets` needs one.")
            self.refs = {s: asset_ref(assets[s], s) for s in need}
            for m in self.markets:
                b, q = m.split("/")
                if self.refs[b] == self.refs[q]:
                    raise ConfigError(f"{m}: both sides name the same asset")
        self.aliases = {k.upper(): v for k, v in cfg.get("symbols", {}).items()}
        self.interval = float(cfg.get("interval", 60))
        static = (cfg.get("source") or {}).get("type") == "static"
        self.flat_rounds = int(cfg.get("flat_rounds", 0 if static else 30))
        self.max_jump = float(cfg.get("max_jump", 0.5))
        self.jump_rounds = max(1, int(cfg.get("jump_rounds", 3)))
        base = os.path.dirname(os.path.abspath(cfg["keyfile"]))
        self.log_v1 = cfg.get("log_v1") or os.path.join(base, "attestations.log")
        self.log_v2 = cfg.get("log_v2") or os.path.join(base, "attestations-v2.log")
        self.status_path = cfg.get("status") or os.path.join(base, "signer-status.json")
        self.source = build_source(cfg)

        keyfile = cfg["keyfile"]
        logs_exist = any(os.path.exists(p) and os.path.getsize(p) > 0
                         for p in (self.log_v1, self.log_v2))
        if os.path.exists(keyfile):
            self.sec = read_key(keyfile)
        elif create_key and not logs_exist:
            self.sec = make_key(keyfile)
        elif logs_exist:
            raise ConfigError(
                f"no oracle key at {keyfile}, but this signer has signed before "
                f"(its logs exist). Restore the backup of its key: a new key "
                f"signs for nothing that pins the old one. Only --create-key on "
                f"a fresh install makes one.")
        else:
            raise ConfigError(f"no oracle key at {keyfile}. Pass --create-key on "
                              f"a fresh install, or restore the backup.")
        self.key = A.xonly_pubkey(self.sec)
        self._lock_fd = None
        self.latest = {}            # market -> (timestamp, price) last signed
        self._flat = {}
        self._jump = {}
        self.errors = {}
        self.source_error = None
        self.frozen = False
        self.last_round = 0.0
        self.signed_at = {}
        self._restore()

    def lock(self):
        """One signer per log. Two writing the same logs would sign two
        attestations for one observation, and each would be published."""
        path = self.log_v2 + ".lock"
        self._lock_fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ConfigError(f"another signer holds {path}; refusing to sign "
                              f"the same logs twice") from None

    def _restore(self):
        """The last price each market was signed at, from the logs, so a
        restart neither re-signs an observation nor forgets the jump guard's
        reference."""
        for d in read_tail(self.log_v1):
            m = canonical(d.get("market", ""))
            if m in self.markets and "price" in d:
                self.latest[m] = (int(d["timestamp"]), int(d["price"]))
        for d in read_tail(self.log_v2):
            m = canonical(d.get("market", ""))
            if m in self.markets and "price" in d and \
                    str(d.get("key", "")).lower() == self.key.hex():
                prev = self.latest.get(m)
                if prev is None or int(d["time"]) >= prev[0]:
                    self.latest[m] = (int(d["time"]), int(d["price"]))

    # -------------------------------------------------------------- signing

    def sign_one(self, market, ts, price):
        """Both records for one observation: (format-1 dict or None,
        AttestationV2 or None)."""
        v1 = v2 = None
        if 1 in self.formats:
            v1 = A.v1_sign(self.sec, market, ts, price, self.price_scale,
                           aux=os.urandom(32))
        if 2 in self.formats:
            b, q = market.split("/")
            v2 = A.AttestationV2(self.key, self.refs[b], self.refs[q], price,
                                 self.precision, ts).sign(self.sec, aux=os.urandom(32))
        return v1, v2

    def tick(self):
        try:
            self.source.refresh()
            source_error = None
        except Exception as e:                     # noqa: BLE001 - reported
            source_error = f"{type(e).__name__}: {e}"
        prices, errors = {}, {}
        for m in self.markets:
            try:
                prices[m] = self.source.price_for(m, self.precisions, self.price_scale,
                                                  self.aliases)
            except Exception as e:                 # noqa: BLE001 - reported
                errors[m] = f"{type(e).__name__}: {e}"
        frozen = False
        if self.flat_rounds:
            # Judged across the whole board: one market may sit still, every
            # market holding the same number for `flat_rounds` is a feed that
            # stopped, whatever its status code says.
            for m, p in prices.items():
                last, n = self._flat.get(m, (None, 0))
                self._flat[m] = (p, n + 1 if p == last else 1)
            frozen = bool(prices) and all(self._flat[m][1] >= self.flat_rounds
                                          for m in prices)
        observed = getattr(self.source, "observed_at", lambda: 0)()
        ts = int(observed or time.time())
        signed = 0
        for m in self.markets:
            if m in errors:
                continue
            try:
                if frozen:
                    raise RuntimeError(
                        f"the feed has returned the same price for every market "
                        f"for {self.flat_rounds} rounds; a price nobody observed "
                        f"is not signed")
                price = prices[m]
                self._jump_guard(m, price)
                if self.latest.get(m) == (ts, price):
                    continue           # this observation is already signed
                if self.latest.get(m, (0, 0))[0] > ts:
                    raise RuntimeError(
                        f"the feed's time went backwards ({ts} after "
                        f"{self.latest[m][0]}); not signing a price older than "
                        f"one already published")
                v1, v2 = self.sign_one(m, ts, price)
                if v2 is not None:
                    append_line(self.log_v2, v2.to_json(market=m))
                if v1 is not None:
                    append_line(self.log_v1, A.v1_line(v1))
                self.latest[m] = (ts, price)
                self.signed_at[m] = time.time()
                signed += 1
            except Exception as e:                 # noqa: BLE001 - reported
                errors[m] = f"{type(e).__name__}: {e}"
        self._report(errors, source_error, frozen)
        self.last_round = time.time()
        self.write_status()
        return signed

    def _jump_guard(self, market, price):
        if not self.max_jump:
            return
        ref = self.latest.get(market, (0, 0))[1]
        if ref <= 0 or abs(price - ref) <= self.max_jump * ref:
            self._jump.pop(market, None)
            return
        held, n = self._jump.get(market, (None, 0))
        n = n + 1 if (held is not None
                      and abs(price - held) <= self.max_jump * max(held, 1)) else 1
        self._jump[market] = (price, n)
        if n < self.jump_rounds:
            raise RuntimeError(
                f"the price moved from {ref} to {price} "
                f"({100.0 * (price - ref) / ref:+.0f}%), further than max_jump "
                f"allows in one step; held {n} of {self.jump_rounds} rounds "
                f"before it is believed. A feed that changed units looks exactly "
                f"like this")
        self._jump.pop(market, None)

    def _report(self, errors, source_error, frozen):
        """Print each transition once, so the journal says when signing stops."""
        for m, e in errors.items():
            if self.errors.get(m) != e:
                say(f"{m}: not signing -- {e}")
        for m in self.errors:
            if m not in errors:
                say(f"{m}: signing again")
        if source_error != self.source_error:
            say(f"feed: {source_error or 'answering again'}")
        if frozen != self.frozen:
            say("the feed is frozen; signing has stopped" if frozen
                else "the feed is moving again")
        self.errors, self.source_error, self.frozen = errors, source_error, frozen

    def status(self):
        skew = getattr(self.source, "clock_skew", None)
        return {
            "key": self.key.hex(),
            "formats": self.formats,
            "precision": self.precision,
            "interval": self.interval,
            "last_round": int(self.last_round),
            "source_error": self.source_error,
            "frozen": self.frozen,
            "clock_skew": None if skew is None else round(skew, 1),
            "markets": {m: {"time": self.latest.get(m, (None, None))[0],
                            "price": self.latest.get(m, (None, None))[1],
                            "error": self.errors.get(m)}
                        for m in self.markets},
            "logs": {"v1": self.log_v1 if 1 in self.formats else None,
                     "v2": self.log_v2 if 2 in self.formats else None},
        }

    def write_status(self):
        """What the web process reports at /healthz, without asking this one."""
        write_atomic(self.status_path, json.dumps(self.status(), sort_keys=True) + "\n")

    def run_forever(self):
        """Sign every `interval` seconds. Five failed rounds in a row exit the
        process for the supervisor to restart, because a signer that quietly
        stopped leaves its last price looking current."""
        failures = 0
        while True:
            started = time.time()
            try:
                self.tick()
                failures = 0
            except Exception as e:                 # noqa: BLE001
                failures += 1
                say(f"signing round failed ({failures}): {type(e).__name__}: {e}")
                if failures >= 5:
                    say("five rounds in a row failed; exiting so the supervisor "
                        "restarts a clean process")
                    sys.exit(1)
            time.sleep(max(1.0, self.interval - (time.time() - started)))


def precision_of_scale(scale):
    """10^p for a price scale, or ValueError: format 2 writes the scale as a
    power of ten, so a format-1 scale of any other number has no format-2 twin."""
    p = round(math.log10(scale)) if scale > 0 else -1
    if p < 0 or 10 ** p != scale:
        raise ValueError(f"price scale {scale} is not a power of ten")
    return p
