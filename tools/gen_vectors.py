#!/usr/bin/env python3
"""Deterministically generate a large differential-test corpus.

Emits spec/vectors/scenarios.json: a mix of hand-picked edge cases plus hundreds
of random DAGs and transactions. Both the Zig node and the Rust reference
implementation consume this file; tools/difftest.sh asserts they agree
byte-for-byte across the whole corpus. Regenerate with: python3 tools/gen_vectors.py
"""
import json
import os
import random

R = random.Random(20260706)  # fixed seed -> reproducible corpus


def hexbytes(n):
    return bytes(R.randrange(256) for _ in range(n)).hex()


def h32():
    return hexbytes(32)


def rand_tx():
    ninputs = R.randrange(0, 4)
    return {
        "version": R.randrange(1, 100),
        "inputs": [{"txid": h32(), "index": R.randrange(0, 5)} for _ in range(ninputs)],
        "outputs": [
            {"value": R.randrange(0, 10**9), "scheme": R.choice([1, 2, 3, 4]), "commitment": h32()}
            for _ in range(R.randrange(1, 4))
        ],
        "witnesses": [
            {"scheme": R.choice([1, 2, 3, 4]), "pubkey": hexbytes(R.randrange(0, 40)), "signature": hexbytes(R.randrange(0, 40))}
            for _ in range(R.randrange(0, 4))
        ],
        "payload": hexbytes(R.randrange(0, 9)),
        "sighash_scheme": R.choice([1, 2, 3, 4]),
    }


def rand_dag(name):
    n = R.randrange(1, 17)
    blocks = []
    for i in range(1, n + 1):
        if i == 1:
            parents = []
        else:
            cnt = R.randrange(1, min(i, 4) + 1 - 1 + 1)  # 1..min(i-1,4)
            cnt = max(1, min(cnt, i - 1))
            parents = R.sample(range(1, i), cnt)
        blocks.append({"id": i, "parents": parents})
    return {"name": name, "k": R.randrange(0, 5), "blocks": blocks}


# --- fixed edge cases (kept from the original curated set) ---
fixed_tx = [
    {"version": 1,
     "inputs": [{"txid": "aa" * 32, "index": 0}],
     "outputs": [{"value": 1000, "scheme": 1, "commitment": "bb" * 32}],
     "witnesses": [{"scheme": 1, "pubkey": "01020304", "signature": "05060708"}],
     "payload": "", "sighash_scheme": 1},
    {"version": 7,
     "inputs": [{"txid": "11" * 32, "index": 3}, {"txid": "22" * 32, "index": 0}],
     "outputs": [{"value": 500, "scheme": 1, "commitment": "cc" * 32},
                 {"value": 499, "scheme": 2, "commitment": "dd" * 32}],
     "witnesses": [{"scheme": 1, "pubkey": "aabb", "signature": "ccdd"},
                   {"scheme": 2, "pubkey": "eeff", "signature": "0011"}],
     "payload": "deadbeef", "sighash_scheme": 2},
    {"version": 1, "inputs": [], "outputs": [{"value": 50, "scheme": 1, "commitment": "99" * 32}],
     "witnesses": [], "payload": "0000000000000000", "sighash_scheme": 1},
]

fixed_dags = [
    {"name": "linear6", "k": 3, "blocks": [{"id": i, "parents": ([i - 1] if i > 1 else [])} for i in range(1, 7)]},
    {"name": "diamond_k1", "k": 1, "blocks": [{"id": 1, "parents": []}, {"id": 2, "parents": [1]}, {"id": 3, "parents": [1]}, {"id": 4, "parents": [2, 3]}]},
    {"name": "diamond_k0", "k": 0, "blocks": [{"id": 1, "parents": []}, {"id": 2, "parents": [1]}, {"id": 3, "parents": [1]}, {"id": 4, "parents": [2, 3]}]},
    {"name": "demo_fork", "k": 3, "blocks": [{"id": 1, "parents": []}, {"id": 2, "parents": [1]}, {"id": 3, "parents": [2]}, {"id": 4, "parents": [2]}, {"id": 5, "parents": [3, 4]}, {"id": 6, "parents": [5]}, {"id": 7, "parents": [6]}]},
]

scenarios = {
    "tx_vectors": fixed_tx + [rand_tx() for _ in range(30)],
    "address_vectors": [{"scheme": R.choice([1, 2, 3, 4]), "pubkey": hexbytes(R.randrange(0, 40))} for _ in range(15)],
    "merkle_vectors": [{"leaves": [h32() for _ in range(R.randrange(0, 9))]} for _ in range(15)],
    "finality_vectors": [{"block": h32(), "blue_score": R.randrange(0, 10**6)} for _ in range(15)],
    "dag_scenarios": fixed_dags + [rand_dag(f"rand{i}") for i in range(300)],
}

out = os.path.join(os.path.dirname(__file__), "..", "spec", "vectors", "scenarios.json")
with open(out, "w") as f:
    json.dump(scenarios, f, indent=1)

print(f"wrote {out}")
print(f"  tx_vectors={len(scenarios['tx_vectors'])} address={len(scenarios['address_vectors'])} "
      f"merkle={len(scenarios['merkle_vectors'])} finality={len(scenarios['finality_vectors'])} "
      f"dags={len(scenarios['dag_scenarios'])}")
