---
title: Recording and replaying transactions
sidebar_position: 7
---

# Recording and replaying transactions

A DAP session driven by `miden-client` can **record** a transaction — the program,
its inputs, the resolved code, and every advice mutation produced by the transaction
host's event handlers — into a self-contained *replay snapshot*. The snapshot can then
be **replayed** offline in the `miden-debug` TUI, with no node, client, or account
state, so you can step through the exact same execution as many times as you like.

This is the simplest way to debug a real note-consumption transaction (e.g. a P2ID
note) end to end.

The examples below use a locally built `miden-client` from the
[miden-client](https://github.com/0xMiden/miden-client) repo (built with the `dap`
feature) and invoke the debugger through `midenup` as `miden debug`.

## Record a note-consumption transaction

The example uses the public testnet, so no local node is needed.

### 1. Create and fund a wallet

```bash
STORE="$HOME/miden-p2id-testnet"
rm -rf "$STORE" && mkdir -p "$STORE"

HOME="$STORE" miden-client init --network testnet
HOME="$STORE" miden-client new-wallet
WALLET=$(HOME="$STORE" miden-client account -l | grep -oE '0x[0-9a-f]+' | head -1)
echo "Fund THIS exact ID at the faucet: $WALLET"
```

Go to the [Miden testnet faucet](https://faucet.testnet.miden.io/), paste `$WALLET`, and
click **Send Public Note**. The faucet sends a P2ID note to your wallet.

> Keep using the same absolute `HOME="$STORE"` on every command — it pins the client's
> store to one location. And fund the *exact* ID that `account -l` prints; a P2ID note
> asserts that the consuming account equals the note's target.

### 2. Find the note

```bash
HOME="$STORE" miden-client sync                              # wait ~20s after funding
HOME="$STORE" miden-client notes -l consumable -a "$WALLET"  # copy the Note ID it lists
```

### 3. Debug and record the consumption

The `consume-notes` command runs the transaction under a DAP server instead of proving
and submitting it, and `--record` writes the replay snapshot when the session ends.

**Terminal 1** — start the debug adapter (replace `<NOTE_ID>` with the ID from step 2):

```bash
HOME="$STORE" miden-client consume-notes -a "$WALLET" <NOTE_ID> \
  --start-debug-adapter 127.0.0.1:4711 \
  --record "$STORE/p2id.mdsnap"
```

**Terminal 2** — attach the debugger and step through the transaction (kernel → note
script → the wallet's `receive_asset`); press `c` to run to the end, `q` to quit:

```bash
miden debug --dap-connect 127.0.0.1:4711
```

When the session ends, Terminal 1 reports the snapshot:

```text
Wrote replay snapshot (542 event(s), 5 forest(s)) to .../p2id.mdsnap
Recorded 542 advice mutation set(s) from event handlers during the debug session.
Wrote replay snapshot to .../p2id.mdsnap; replay it with `miden-debug --replay .../p2id.mdsnap`.
```

## Replay offline

```bash
miden debug --replay "$STORE/p2id.mdsnap"
```

The recorded events are fed back through the debugger's event-replay host, so you step
through the identical execution — no network or wallet required. The snapshot carries no
source files, so the debugger shows disassembly.

To generate a cycle-weighted flamegraph from the same transaction without an interactive
debugging session, enable the debugger's `flamegraph` feature and run:

```bash
miden debug flamegraph --replay "$STORE/p2id.mdsnap" -o p2id.svg
```

## Replaying a failed transaction

A snapshot is written even when the debugged transaction **fails** mid-execution (for
example, a note-script assertion). This captures the run up to the failure point, so you
can replay a failing consume offline and step right up to where it went wrong — often the
most useful case to debug.
