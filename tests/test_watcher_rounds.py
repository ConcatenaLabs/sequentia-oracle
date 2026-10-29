#!/usr/bin/env python3
# Copyright (c) 2026 The Sequentia developers
# Distributed under the MIT software license.
"""The watcher's rounds without a node: a record of an oracle's log is verified
once, however many rounds read it, so a round's cost follows what is new in the
log, not the log's length."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from sequentia_oracle import watcher as W         # noqa: E402


class FakeNode:
    def __init__(self):
        self.calls = 0

    def __getattr__(self, name):
        def call(*a, **k):
            self.calls += 1
            raise AssertionError("no node call is expected while reading logs: %s" % name)
        return call


class VerifiesOnce(unittest.TestCase):
    def test_a_record_is_verified_once(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "attestations.log")
        with open(log, "w") as f:
            for i in range(200):
                f.write(json.dumps({"message": "%064x" % i, "signature": "%0128x" % i}) + "\n")
        node = FakeNode()
        w = W.Watcher({"state": os.path.join(d, "state.json")}, node=node)
        oracle = {"key": "11" * 32, "logs": [log], "name": "o"}
        calls = []
        real = W.signed_by
        W.signed_by = lambda key, rec: calls.append(rec) or real(key, rec)
        try:
            w.read(oracle)
            self.assertEqual(len(calls), 200, "the first round verifies every record")
            w.read(oracle)
            self.assertEqual(len(calls), 200, "a second round verifies nothing again")
            with open(log, "a") as f:
                for i in range(200, 202):
                    f.write(json.dumps({"message": "%064x" % i, "signature": "%0128x" % i}) + "\n")
            w.read(oracle)
            self.assertEqual(len(calls), 202, "a round verifies only what is new")
            # another oracle's key over the same log is its own check
            w.read(dict(oracle, key="22" * 32))
            self.assertEqual(len(calls), 404)
        finally:
            W.signed_by = real
        self.assertEqual(node.calls, 0)


if __name__ == "__main__":
    unittest.main()


class Restarts(unittest.TestCase):
    """A restart verifies nothing an earlier run indexed, and a round that changes
    nothing writes nothing."""

    def test_a_restart_verifies_only_what_is_new(self):
        import test_bond as TB
        d = tempfile.mkdtemp()
        log = os.path.join(d, "attestations.log")
        t = 1790000000
        with open(log, "w") as f:
            for i in range(20):
                f.write(json.dumps(TB.att(TB.SEC_A, 300 + i, t + 60 * i)) + "\n")
        oracle = {"key": TB.KEY_A.hex(), "logs": [log], "name": "o"}
        state = os.path.join(d, "state.json")
        calls = []
        real = W.signed_by
        W.signed_by = lambda key, rec: calls.append(rec) or real(key, rec)
        try:
            w = W.Watcher({"state": state, "retain_days": 100000}, node=FakeNode())
            w.read(oracle); w.save()
            self.assertEqual(len(calls), 20, "the first run verifies every record")
            seen = sum(len(v) for v in w.state["seen"][oracle["key"]].values())
            self.assertEqual(seen, 20)
            mtime = os.stat(state).st_mtime_ns
            w.read(oracle); w.save()
            self.assertEqual(os.stat(state).st_mtime_ns, mtime, "a round that changes nothing writes nothing")
            w2 = W.Watcher({"state": state, "retain_days": 100000}, node=FakeNode())   # a restart
            with open(log, "a") as f:
                f.write(json.dumps(TB.att(TB.SEC_A, 999, t + 60 * 20)) + "\n")
            w2.read(oracle)
            self.assertEqual(len(calls), 21, "after a restart only the new record is verified")
        finally:
            W.signed_by = real
