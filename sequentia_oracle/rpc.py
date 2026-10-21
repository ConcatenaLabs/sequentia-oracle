# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""A node's JSON-RPC, for the bond tool and the watcher.

Credentials are read where they already live: the node's cookie file, or a
user and a file holding the password. They are never printed, logged or put
in an error message.
"""

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

# Wallets that hold reserves, a bridge's or a treasury's coins, and the wallets
# of other services (a bridge such as Compages, an escrow such as SeqPal's, a
# beacon, a faucet): the bond tool funds and pays fees from the wallet it is
# told to, and never from one of these, so a typo cannot move them.
REFUSED_WALLETS = re.compile(r"reserve|sbtc|bridge|treasury|compages|seqpal|escrow|beacon|faucet", re.I)


class RPCError(Exception):
    def __init__(self, method, error):
        self.method, self.error = method, error
        super().__init__(f"{method}: {error.get('message') if isinstance(error, dict) else error}")


def check_wallet_name(name):
    if not name or not isinstance(name, str):
        raise SystemExit("name the wallet that pays: `wallet` in the config")
    if REFUSED_WALLETS.search(name):
        raise SystemExit(f"refusing wallet {name!r}: a reserve, SBTC, bridge or treasury wallet, or "
                         "another service's (Compages, an escrow, a beacon, a faucet), never funds a bond "
                         "or pays its fees. Name an operating wallet")
    return name


class Node:
    def __init__(self, url, cookie=None, user=None, password_file=None, wallet=None, timeout=60):
        self.url = url.rstrip("/")
        self.timeout = timeout
        if cookie:
            with open(cookie) as f:
                cred = f.read().strip()
        elif user and password_file:
            with open(password_file) as f:
                cred = user + ":" + f.read().strip()
        else:
            raise SystemExit("rpc needs `cookie`, or `user` and `password_file`")
        self._auth = "Basic " + base64.b64encode(cred.encode()).decode()
        self.wallet = wallet

    @classmethod
    def from_config(cls, rpc, wallet=None):
        odd = sorted(set(rpc) - {"url", "cookie", "user", "password_file", "timeout"})
        if odd:
            raise SystemExit(f"rpc does not understand {', '.join(odd)}")
        return cls(rpc["url"], rpc.get("cookie"), rpc.get("user"), rpc.get("password_file"), wallet,
                   float(rpc.get("timeout", 60)))

    def call(self, method, *params, wallet=True, **named):
        url = self.url
        if wallet and self.wallet:
            url += "/wallet/" + urllib.parse.quote(self.wallet, safe="")
        body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method,
                           "params": named if named else list(params)}).encode()
        req = urllib.request.Request(url, data=body, headers={"Authorization": self._auth,
                                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                out = json.loads(e.read())
            except ValueError:
                raise RPCError(method, f"HTTP {e.code}") from None
        if out.get("error"):
            raise RPCError(method, out["error"])
        return out["result"]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: self.call(name, *a, **k)
