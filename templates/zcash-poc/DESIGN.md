# Zcash-Inspired Shielded Pool PoC

## What Was Built

A working Substrate solochain template (`templates/zcash-poc/`) with a custom `pallet-shielded-pool` that demonstrates **confidential value transfers** using Pedersen commitments on the Pallas elliptic curve.

This builds on the new Pallas/Vesta host functions added to `sp-crypto-ec-utils` (PR #11035), which provide efficient multi-scalar multiplication and scalar multiplication on these curves at the host level.

## What Privacy Does This Provide?

**Value privacy (implemented):** All amounts in the shielded pool are hidden. When notes are transferred, the chain verifies that inputs and outputs balance using homomorphic properties of the commitments — without ever learning the individual values. This is the core cryptographic primitive that Zcash is built on, and it works end-to-end in this PoC.

**Sender/receiver privacy (not yet):** Extrinsics are still signed by an account, so observers can see *who* is calling mint/transfer/burn. In full Zcash, ZK proofs (Halo 2 circuits) let users prove note ownership without revealing their identity. Adding ZK proof verification is the natural next step — the value-hiding layer built here is the foundation it sits on.

## How It Works

### Pedersen Commitments

Each shielded note is represented on-chain as a Pedersen commitment:

```
C = value * G + blinding * H
```

where G is the Pallas generator and H is a deterministically derived second generator. The commitment hides both the value and the blinding factor. Only the blake2_256 hash of the serialized curve point is stored on-chain.

### Extrinsics

The pallet exposes three operations:

- **Mint** - Deducts from the sender's public balance and creates a commitment in the shielded pool.
- **Transfer** - Spends existing shielded notes (via nullifiers) and creates new ones. Balance conservation is verified homomorphically: `sum(C_in) - sum(C_out) == balance_blinding * H`. No individual values are revealed.
- **Burn** - Reveals the value and blinding factor to withdraw from the shielded pool back to a public balance.

### Double-Spend Prevention

Each note can only be spent once. When spending, the user publishes a nullifier (a unique identifier for the note). The chain maintains a set of seen nullifiers and rejects duplicates.

## Path to Full Privacy

The PoC implements the hard part — homomorphic value hiding on Pallas with host-accelerated curve operations. To reach full Zcash-level privacy, the remaining pieces are:

1. **ZK proof verification** (Halo 2) - Prove note ownership and transaction validity without revealing sender, receiver, or amounts. This is what turns value privacy into full transaction privacy.
2. **Range proofs** - Prevent negative-value notes that could inflate supply.
3. **Merkle tree commitments** - Prove a note exists in the set without revealing which one.
4. **Encrypted memos** - Allow the receiver to learn the note details off-chain.

## Test Coverage

20 unit tests pass covering:
- Commitment math (create, verify, homomorphic property, serialization roundtrip)
- Homomorphic balance verification (balanced and unbalanced cases)
- Pallet logic (mint, burn, transfer with correct balances)
- Error cases (duplicate commitments, double-spend, wrong blinding, insufficient balance)
- Full lifecycle (mint -> transfer -> burn)

## Code Structure

```
templates/zcash-poc/
  pallets/shielded-pool/src/
    commitment.rs   -- Pedersen commitment math using Pallas MSM host functions
    lib.rs          -- Pallet storage, events, errors, and extrinsics
    mock.rs         -- Test mock runtime
    tests.rs        -- Integration tests
  runtime/          -- Solochain runtime with the pallet wired in
  node/             -- Node binary (forked from solochain template)
```
