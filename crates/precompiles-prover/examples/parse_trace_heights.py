#!/usr/bin/env python3
"""Parse a `dump_trace_heights` log into one JSON object per swept combo.

Usage:
    python3 parse_trace_heights.py heights.log > results.jsonl

Input is the line-oriented stderr log produced by
`cargo run --release --example dump_trace_heights`:

    COMBO keccaks=<k> ecdsas=<e>
    REAL_HEIGHT <ChipletName> <rows>
    PADDED_HEIGHT <ChipletName> <rows>
    PROVE_MS <milliseconds>

`PROVE_MS` times only the `prove_once_with_hash` call (wall-clock,
single sample, no warm-up) — a rough per-combo comparison point, not a
criterion-grade benchmark.

Three chiplets are merged AIRs assembled from multiple sub-traces sharing
one row range, so their real height is reported as several separate
`REAL_HEIGHT` probes and combined here via `max`:
  - ChunkNodeSponge: max(ChunkNodeSponge_chunk, ChunkNodeSponge_node, ChunkNodeSponge_sponge)
  - UintStoreMul: max(UintStoreMul_store, UintStoreMul_mul)
  - EcPointStoreGroups: max(EcPointStoreGroups_points, EcPointStoreGroups_groups)

`BytePairLut` has no `REAL_HEIGHT` probe (its trace is a fixed-size
lookup table, not workload-driven) — its real height is read from its
own `PADDED_HEIGHT` line, since real == padded == TRACE_HEIGHT always.

Each output line is a JSON object:
    {"keccaks": <k>, "ecdsas": <e>, "prove_ms": <ms>,
     "<ChipletName>": [real, padded, wastePct], ...}
where wastePct = round((padded - real) / padded * 100, 1).
"""

import json
import re
import sys

# Chiplets with a single REAL_HEIGHT probe under this exact name.
SIMPLE_CHIPLETS = [
    "EidosCompression",
    "Round",
    "TranscriptEval",
    "UintAdd",
    "EcGroupAdd",
    "EcMsm",
]

# Chiplets whose real height is the max of several split probes.
SPLIT_CHIPLETS = {
    "ChunkNodeSponge": (
        "ChunkNodeSponge_chunk",
        "ChunkNodeSponge_node",
        "ChunkNodeSponge_sponge",
    ),
    "UintStoreMul": ("UintStoreMul_store", "UintStoreMul_mul"),
    "EcPointStoreGroups": ("EcPointStoreGroups_points", "EcPointStoreGroups_groups"),
}

ALL_CHIPLETS = list(SPLIT_CHIPLETS) + SIMPLE_CHIPLETS + ["BytePairLut"]

COMBO_RE = re.compile(r"^COMBO keccaks=(\d+) ecdsas=(\d+)$")
HEIGHT_RE = re.compile(r"^(REAL_HEIGHT|PADDED_HEIGHT) (\S+) (\d+)$")
PROVE_MS_RE = re.compile(r"^PROVE_MS (\d+)$")


def waste_pct(real: int, padded: int) -> float:
    if padded == 0:
        return 0.0
    return round((padded - real) / padded * 100, 1)


def flush_combo(keccaks, ecdsas, real, padded, prove_ms):
    """Build one combo's JSON record from its accumulated probes."""
    if keccaks is None:
        return None

    record = {"keccaks": keccaks, "ecdsas": ecdsas, "prove_ms": prove_ms}

    for name, probe_names in SPLIT_CHIPLETS.items():
        r = max(real.get(probe_name, 0) for probe_name in probe_names)
        p = padded.get(name, 0)
        record[name] = [r, p, waste_pct(r, p)]

    for name in SIMPLE_CHIPLETS:
        r = real.get(name, 0)
        p = padded.get(name, 0)
        record[name] = [r, p, waste_pct(r, p)]

    # Fixed-size lookup table: real == padded always.
    bpl_height = padded.get("BytePairLut", 0)
    record["BytePairLut"] = [bpl_height, bpl_height, 0.0]

    return record


def parse(lines):
    keccaks = ecdsas = prove_ms = None
    real = {}
    padded = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        combo_match = COMBO_RE.match(line)
        if combo_match:
            record = flush_combo(keccaks, ecdsas, real, padded, prove_ms)
            if record is not None:
                yield record
            keccaks, ecdsas = int(combo_match.group(1)), int(combo_match.group(2))
            real, padded, prove_ms = {}, {}, None
            continue

        height_match = HEIGHT_RE.match(line)
        if height_match:
            kind, name, value = height_match.groups()
            (real if kind == "REAL_HEIGHT" else padded)[name] = int(value)
            continue

        prove_ms_match = PROVE_MS_RE.match(line)
        if prove_ms_match:
            prove_ms = int(prove_ms_match.group(1))

    record = flush_combo(keccaks, ecdsas, real, padded, prove_ms)
    if record is not None:
        yield record


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} heights.log", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        for record in parse(f):
            print(json.dumps(record))


if __name__ == "__main__":
    main()
