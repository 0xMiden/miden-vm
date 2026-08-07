#!/usr/bin/env python3
"""Parse a `dump_trace_heights` log into one JSON object per swept combo.

Usage:
    python3 parse_trace_heights.py heights.log > results.jsonl

Input is the line-oriented stderr log produced by
`cargo run --release --example dump_trace_heights`:

    COMBO keccaks=<k> ecdsas=<e>
    REAL_HEIGHT <ChipletName> <rows>
    PADDED_HEIGHT <ChipletName> <rows>
    PROVE_TIME_MS <ms>

Two chiplets are assembled from a pair of sub-traces sharing one row
range, so their real height is reported as two separate `REAL_HEIGHT`
probes and combined here via `max`:
  - ChunkNode: max(ChunkNode_chunk, ChunkNode_node)
  - UintStoreMul: max(UintStoreMul_mul, UintStoreMul_store)

`BytePairLut` has no `REAL_HEIGHT` probe (its trace is a fixed-size
lookup table, not workload-driven) — its real height is read from its
own `PADDED_HEIGHT` line, since real == padded == TRACE_HEIGHT always.

Each output line is a JSON object:
    {"keccaks": <k>, "ecdsas": <e>, "prove_ms": <ms or null>,
     "<ChipletName>": [real, padded, wastePct], ...}
where wastePct = round((padded - real) / padded * 100, 1). `prove_ms` is
null if the log has no `PROVE_TIME_MS` line for that combo (older logs
predate timing instrumentation).
"""

import json
import re
import sys

# Chiplets with a single REAL_HEIGHT probe under this exact name.
SIMPLE_CHIPLETS = [
    "Poseidon2",
    "Round",
    "KeccakSponge",
    "TranscriptEval",
    "UintAdd",
    "EcGroups",
    "EcPointStore",
    "EcGroupAdd",
    "EcMsm",
]

# Chiplets whose real height is the max of two split probes.
SPLIT_CHIPLETS = {
    "ChunkNode": ("ChunkNode_chunk", "ChunkNode_node"),
    "UintStoreMul": ("UintStoreMul_mul", "UintStoreMul_store"),
}

ALL_CHIPLETS = list(SPLIT_CHIPLETS) + SIMPLE_CHIPLETS + ["BytePairLut"]

COMBO_RE = re.compile(r"^COMBO keccaks=(\d+) ecdsas=(\d+)$")
HEIGHT_RE = re.compile(r"^(REAL_HEIGHT|PADDED_HEIGHT) (\S+) (\d+)$")
PROVE_TIME_RE = re.compile(r"^PROVE_TIME_MS (\d+)$")


def waste_pct(real: int, padded: int) -> float:
    if padded == 0:
        return 0.0
    return round((padded - real) / padded * 100, 1)


def flush_combo(keccaks, ecdsas, real, padded, prove_ms):
    """Build one combo's JSON record from its accumulated probes."""
    if keccaks is None:
        return None

    record = {"keccaks": keccaks, "ecdsas": ecdsas, "prove_ms": prove_ms}

    for name, (a, b) in SPLIT_CHIPLETS.items():
        r = max(real.get(a, 0), real.get(b, 0))
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

        prove_time_match = PROVE_TIME_RE.match(line)
        if prove_time_match:
            prove_ms = int(prove_time_match.group(1))

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
