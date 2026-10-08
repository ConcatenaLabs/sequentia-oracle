# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""Price sources: where the signer reads the numbers it signs.

A source returns the price of one whole unit of a symbol in the feed's
reference currency (for the Sequentia price server, US dollars). The signer
turns two of those into a pair's integer price with `quote_price`.
"""

import json
import time

# ------------------------------------------------------------------ pricing

def quote_price(base_ref: float, quote_ref: float,
                base_precision: int = 8, quote_precision: int = 8,
                price_scale: int = 100_000) -> int:
    """Convert two reference-currency prices into a pair's integer price.

    `base_ref` and `quote_ref` are prices of one WHOLE UNIT of each asset in
    the same reference currency (whatever the price feed quotes in -- for the
    Sequentia price server that is USD). Precisions are the assets' decimal
    places.

        price = round( (base_ref / quote_ref)
                       * 10**(quote_precision - base_precision)
                       * price_scale )

    Worked example. GOLD at 3,000 USD, USDX at 1 USD, both 8 decimals,
    price_scale 1e5:

        (3000 / 1) * 10**0 * 1e5 = 300_000_000

    Divide by the scale and that reads as 3,000 quote atoms per base atom.
    Check it the long way round: one GOLD atom is 1e-8 GOLD = 3e-5 USD, and one
    USDX atom is 1e-8 USD, so a GOLD atom is worth 3,000 USDX atoms. The two
    readings agree.

    When the assets have EQUAL precision the atoms-per-atom figure equals the
    unit price, which is why it is easy to write 300 here by reflex and why
    tests/test_signer.py pins this exact number.
    """
    if quote_ref <= 0:
        raise ValueError("the quote side's reference price must be positive")
    if base_ref < 0:
        raise ValueError("the base side's reference price cannot be negative")
    scaled = (base_ref / quote_ref) * (10 ** (quote_precision - base_precision))
    price = round(scaled * price_scale)
    if price <= 0:
        raise ValueError(
            f"price rounds to {price} at price_scale={price_scale}: the "
            "base is too cheap relative to the quote at this precision. "
            "Raise the precision.")
    if price >= (1 << 63):
        raise ValueError(f"price {price} overflows 64 bits; lower the precision")
    return price


def unquote_price(price: int, base_precision: int = 8,
                  quote_precision: int = 8, price_scale: int = 100_000) -> float:
    """The inverse of quote_price: how many whole quote units one whole
    base unit is worth. For display only."""
    return (price / price_scale) * (10 ** (base_precision - quote_precision))


# ------------------------------------------------------------- price sources

class PriceSource:
    """Where prices come from. Subclasses supply `reference_price(symbol)` in the
    feed's reference currency."""

    def refresh(self) -> None:
        """Take one snapshot, for a source that has one. Called once at the top
        of a signing round so that every market in the round is priced from the
        same numbers; sources without a snapshot do nothing."""

    def reference_price(self, symbol: str) -> float:
        raise NotImplementedError

    def price_for(self, market: str, precisions=None, price_scale=100_000,
                  aliases=None) -> int:
        """The integer price for `market` ("BASE/QUOTE") at `price_scale`.

        `aliases` maps a market's asset name to the ticker the feed knows it by.
        The Sequentia demo feed quotes Bitcoin as `tBTC`, for instance, while a
        market is naturally written `BTC/USDX` -- and the market NAME is what the
        feed id commits to, so renaming the market to suit the feed would change
        every vault address that references it. Aliasing the lookup instead
        leaves the on-chain identity alone.
        """
        base_sym, quote_sym = [p.strip().upper() for p in market.split("/")]
        precisions = precisions or {}
        aliases = {k.upper(): v for k, v in (aliases or {}).items()}
        return quote_price(
            self.reference_price(aliases.get(base_sym, base_sym)),
            self.reference_price(aliases.get(quote_sym, quote_sym)),
            precisions.get(base_sym, 8),
            precisions.get(quote_sym, 8),
            price_scale)


class StaticPriceSource(PriceSource):
    """Fixed prices. For tests, for drills, and for an operator who wants to pin
    a feed deliberately -- which is visible, because every attestation is
    published."""

    def __init__(self, prices: dict):
        self.prices = {k.upper(): float(v) for k, v in prices.items()}

    def reference_price(self, symbol: str) -> float:
        try:
            return self.prices[symbol.upper()]
        except KeyError:
            raise KeyError(f"no static price configured for {symbol}") from None


class BulkHttpPriceSource(PriceSource):
    """Reads every price in ONE request from a `/prices`-style endpoint.

    Preferred over per-symbol fetching for two reasons. It is one request per
    signing round instead of one per market, and -- more importantly -- every
    price in a round comes from the same snapshot, so two markets cannot be
    signed against feeds that moved between them.

    Lookups are case-insensitive, because feed tickers are not consistently
    cased (the Sequentia demo feed serves `tBTC`) and a price that is present but
    unreachable because of capitalisation is the most annoying possible outage.

    Two ages, and they answer different questions. `max_age` is how long a
    snapshot this oracle already holds may go on being signed when the feed
    stops answering: a brief outage should not stop the oracle, and a long one
    must. `feed_max_age` is how stale the feed says its OWN numbers are -- a
    price server whose upstream died keeps serving its last prices, and an
    oracle that re-signs those with a fresh timestamp is manufacturing
    freshness that does not exist. Both refuse rather than guess, because a
    refusal is visible in `/healthz` and in `/v1/markets` while a stale number
    is not.
    """

    def __init__(self, url: str, timeout: float = 8.0, field: str = "price",
                 max_age: float = 300.0, feed_max_age: float = 0.0):
        self.url = url
        self.timeout = timeout
        self.field = field
        self.max_age = max_age
        self.feed_max_age = feed_max_age
        self._snapshot = {}
        self._fetched = 0.0
        self._updated = 0.0
        self.clock_skew = None

    def observed_at(self) -> float:
        """When the prices held were observed: what the feed says of its own
        numbers when it says anything, else when this oracle read them."""
        return self._updated or self._fetched

    def refresh(self) -> None:
        body, skew = fetch_feed(self.url, self.timeout)
        data = json.loads(body.decode())
        if skew is not None:
            self.clock_skew = skew
        if not isinstance(data, dict):
            raise ValueError(f"{self.url} did not return an object")
        meta = data.get("_meta") or {}
        self._snapshot = {k.lower(): v for k, v in data.items()}
        self._fetched = time.time()
        self._updated = float(meta.get("updated") or 0) if isinstance(meta, dict) else 0.0

    def reference_price(self, symbol: str) -> float:
        # No fetching from here. The round takes one snapshot and prices every
        # market from it, so two markets in the same round cannot be signed
        # against feeds that moved between them.
        if not self._fetched:
            raise ValueError(f"{self.url} has not been read yet")
        age = time.time() - self._fetched
        if self.max_age and age > self.max_age:
            raise ValueError(
                f"{self.url} was last read {int(age)}s ago (limit "
                f"{int(self.max_age)}s); refusing to sign a stale snapshot")
        if self.feed_max_age and not self._updated:
            # ASKED FOR and unanswerable. `feed_max_age` is off unless an
            # operator sets it, because a feed is not obliged to publish
            # `_meta.updated` and most do not -- so a default that refused
            # would break every deployment pointing at one, including the mock
            # price server this project ships.
            #
            # But an operator who DID set it believes a stale feed will be
            # caught, and silently treating "cannot tell" as "fresh" is the
            # worst of both. So the check they asked for is either performed or
            # refused, never quietly skipped.
            raise ValueError(
                f"{self.url} publishes no `_meta.updated`, so `feed_max_age` "
                f"({int(self.feed_max_age)}s) cannot be checked at all. A feed "
                f"that cannot say when it last moved could be frozen at a "
                f"price from a week ago and look perfectly current. Point at a "
                f"feed that publishes it, or remove `feed_max_age` (it is off "
                f"by default) to sign without the check.")
        if self.feed_max_age and self._updated:
            fed = time.time() - self._updated
            if fed > self.feed_max_age:
                raise ValueError(
                    f"{self.url} last updated its own prices {int(fed)}s ago "
                    f"(limit {int(self.feed_max_age)}s); refusing to sign a "
                    "stale feed")
        row = self._snapshot.get(symbol.lower())
        if row is None:
            raise KeyError(
                f"{symbol} is not in {self.url} "
                f"(have: {', '.join(sorted(self._snapshot)[:12])})")
        # `bool` is an int to Python, and a feed answering `true` where a
        # number belongs -- an error flag from a JavaScript feed, say -- would
        # be signed as a price of exactly 1. Every loan on that market would
        # then be liquidatable against a number nobody observed.
        if isinstance(row, bool):
            raise ValueError(f"{symbol} is a boolean in {self.url}, not a price")
        if isinstance(row, (int, float)):
            return float(row)
        if self.field not in row:
            raise KeyError(f"{symbol} has no '{self.field}' field: {row}")
        if isinstance(row[self.field], bool):
            raise ValueError(f"{symbol}'s '{self.field}' is a boolean in "
                             f"{self.url}, not a price")
        return float(row[self.field])


# How far this machine's clock may sit from a feed's before an attestation
# stamped here is refused downstream as from the future or already stale.
CLOCK_TOLERANCE = 60.0
# The most a feed may say in one answer. A price is a few bytes.
FEED_MAX_BYTES = 1_000_000


def check_feed_url(url: str, insecure: bool = False) -> None:
    """A plain-http feed on another machine is one a path in between can
    rewrite, and an oracle signs the rewrite. Refused at start unless the
    operator says `insecure` on purpose."""
    from urllib.parse import urlparse
    u = urlparse(str(url))
    host = (u.hostname or "").lower()
    if u.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1") \
            and not host.startswith("127.") and not insecure:
        raise SystemExit(
            f"the price feed {url} is plain http on another machine, which a "
            f"path in between can rewrite -- and this oracle would sign the "
            f"rewrite. Use https, a loopback feed, or set "
            f"\"insecure\": true in the source to say this is deliberate.")
    if u.scheme not in ("http", "https"):
        raise SystemExit(f"the price feed {url} is not an http(s) URL")


_OPENER = None


def fetch_feed(url: str, timeout: float):
    """(bytes, clock skew in seconds or None): the body, capped, and how far
    this machine's clock is from the feed's Date header. A redirect is
    refused: a feed that moved is not the one the operator checked."""
    global _OPENER
    import urllib.request
    from email.utils import parsedate_to_datetime
    if _OPENER is None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                raise ValueError("the feed redirected; refusing to follow")
        _OPENER = urllib.request.build_opener(_NoRedirect())
    with _OPENER.open(url, timeout=timeout) as r:
        body = r.read(FEED_MAX_BYTES + 1)
        if len(body) > FEED_MAX_BYTES:
            raise ValueError(f"{url} answered more than {FEED_MAX_BYTES} "
                             f"bytes; a price feed does not")
        skew = None
        date = r.headers.get("Date")
        if date:
            try:
                skew = time.time() - parsedate_to_datetime(date).timestamp()
            except Exception:                           # noqa: BLE001
                skew = None
    return body, skew


class HttpPriceSource(PriceSource):
    """Reads the Sequentia price feed already deployed for the any-asset fee
    market (contrib/price-server). Deliberately not a second price pipeline:
    one source of prices for fees and for loans means one thing to operate and
    one thing to be wrong."""

    def __init__(self, url: str, timeout: float = 5.0, field: str = "price",
                 feed_max_age: float = 0.0, max_age: float = 0.0):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.field = field
        self.feed_max_age = feed_max_age
        # How long one symbol's answer may be reused, in seconds. Zero means
        # every call fetches, which is the safe default for a source that
        # fetches per symbol; the bulk source takes one snapshot per round and
        # so has a different shape of the same question.
        self.max_age = max_age
        self._cache = {}
        self._fetched = 0.0
        self.clock_skew = None

    def observed_at(self) -> float:
        return self._fetched

    def reference_price(self, symbol: str) -> float:
        # NOT upper-cased: feed tickers are case-sensitive (the Sequentia demo
        # feed serves `tBTC`, and `TBTC` is a 404).
        url = f"{self.url}/{symbol}"
        hit = self._cache.get(symbol)
        if hit and self.max_age and (time.time() - hit[0]) <= self.max_age:
            return hit[1]
        body, skew = fetch_feed(url, self.timeout)
        data = json.loads(body.decode())
        self._fetched = time.time()
        if skew is not None:
            self.clock_skew = skew
        if isinstance(data, bool):
            raise ValueError(f"{url} returned a boolean, not a price")
        if isinstance(data, (int, float)):
            return float(data)
        if self.field not in data:
            raise KeyError(f"{url} returned no '{self.field}' field: {data}")
        # A feed that dates its own answer is taken at its word: re-signing a
        # price the feed itself says is hours old would put this oracle's
        # signature and a fresh timestamp on a number nobody stands behind.
        updated = data.get("updated") if isinstance(data, dict) else None
        if self.feed_max_age and not updated:
            # ASKED FOR and unanswerable, exactly as the bulk source treats it.
            # `feed_max_age` is off unless an operator sets it; having set it,
            # a feed that dates nothing cannot answer the question, and
            # "cannot tell" must not be read as "fresh".
            raise ValueError(
                f"{url} publishes no `updated`, so this oracle cannot check "
                f"how old its numbers are -- and feed_max_age asks it to. "
                f"Point at a feed that dates its answers, or unset it.")
        if self.feed_max_age and updated:
            age = time.time() - float(updated)
            if age > self.feed_max_age:
                raise ValueError(
                    f"{url} was last updated {int(age)}s ago (limit "
                    f"{int(self.feed_max_age)}s); refusing to sign a stale feed")
        price = float(data[self.field])
        self._cache[symbol] = (time.time(), price)
        return price

