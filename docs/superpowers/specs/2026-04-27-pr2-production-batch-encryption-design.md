# PR #2 Production Batch Encryption Design

**Status:** Approved design direction

**Date:** 2026-04-27

**Source PR:** https://github.com/synchronicity-xyz/sovereign-sdk/pull/2

## Goal

Bring PR #2 to a production-ready native full-node feature that encrypts preferred sequencer transaction batches before DA submission and decrypts them in the native STF path using one configured AES-256-GCM key.

## Non-Goals

- Do not support encrypted batch proving inside SP1 or Risc0 guests in this phase.
- Do not implement live key rotation in this phase.
- Do not implement a Unix socket key listener in this phase.
- Do not keep multi-key fallback, brute-force decrypt, or historical key pruning behavior in this phase.
- Do not introduce a full external key management service integration yet.

## Production Scope

The production feature supports a single static encryption key supplied through rollup configuration. In deployment this config will eventually be managed through SOPS or an equivalent secret distribution path.

The implementation should still be shaped around a small key-provider boundary so a future key management service can be added without rewriting sequencer or STF encryption flow.

## Current PR State

PR #2 currently:

- Adds `crates/utils/sov-encryption`.
- Adds batch encryption in `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`.
- Adds batch decryption in `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`.
- Threads an optional `EncryptionLayer` through the rollup blueprint, sequencer, STF blueprint, and blob storage.
- Contains unused or out-of-scope complexity for this production target: Unix socket config, key queues, key rotation messages, key ID fallback, key pruning, and multi-key decrypt attempts.

The branch is conflict-free at its own head for core checks, but conflicts with current `dev-sync`.

Observed merge conflicts against current `origin/dev-sync`:

- `.github/workflows/rust.yml.disabled`
- `Cargo.lock`
- `crates/full-node/sov-sequencer/src/preferred/initialization.rs`
- `crates/module-system/sov-modules-stf-blueprint/src/lib.rs`
- `examples/demo-rollup/provers/risc0/guest-celestia/Cargo.lock`
- `examples/demo-rollup/provers/sp1/guest-celestia/Cargo.lock`
- `examples/demo-rollup/provers/sp1/guest-mock/Cargo.lock`

Local verification on the PR head:

- `SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption --all-features` passed 17 tests.
- `SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-sequencer -p sov-blob-storage -p sov-modules-stf-blueprint --all-features` passed.
- `SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-stf-blueprint --no-default-features` passed.
- `SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-blob-storage --no-default-features` passed.

## Architecture

### Key Provider Boundary

Introduce a small native-only key provider boundary owned by `sov-encryption`.

The boundary should express one operation:

- Return the active batch encryption key.

For this phase there is exactly one implementation:

- Static config provider backed by a validated 32-byte AES key.

The sequencer and STF should depend on the encryption layer, not on how the key is sourced. The implementation should avoid designing the full future KMS API now. The boundary exists to isolate the future change.

### Encryption Layer

`sov-encryption` should become a focused crate for:

- Redacted key config types.
- Static key validation.
- AES-256-GCM encrypt/decrypt.
- A simple encrypted payload envelope format.
- Unit tests for cryptographic and validation behavior.

It should not contain:

- Unix socket listener code.
- Queue-based key cache.
- Multiple key fallback.
- Historical key pruning.
- Key rotation message types.

The static key must be:

- Hex encoded in config.
- Exactly 32 bytes after decoding.
- Rejected if all bytes are zero.
- Redacted in `Debug`.

### Batch Format

Preferred sequencer batches should support two wire formats:

- Existing unencrypted `PreferredBatchData`.
- New encrypted batch wrapper containing encrypted transaction bytes and metadata.

The encrypted wrapper should include:

- Batch sequence number.
- Visible slots to advance.
- Encrypted serialized transaction vector.
- Encryption format version.

It should not include transaction hashes. The sequencer status path keeps transaction hashes in local blob-sender bookkeeping keyed by blob ID, so publishing hashes in the DA envelope would leak transaction fingerprints without a current consumer.

Key ID is optional for the static-key phase. If retained, it should be a constant or clearly documented as metadata only. The decrypt path must not depend on key lookup by ID in this phase.

### Sequencer Flow

When encryption is disabled:

- `PreferredBlobSender` serializes `PreferredBatchData` exactly as before.

When encryption is enabled:

- `PreferredBlobSender` serializes the transaction vector.
- It encrypts the serialized transaction bytes with the configured static key.
- It serializes the encrypted batch wrapper.
- Proof blobs are not encrypted.
- Recovery publication must use the same path as normal publication so completed batches are re-encrypted deterministically by behavior but not by ciphertext bytes. AES-GCM nonce randomness means ciphertext bytes differ across attempts, which is acceptable because decrypting restores the same transactions.

### STF and Blob Storage Flow

When encryption is disabled:

- Blob storage deserializes preferred batches as `PreferredBatchData` exactly as before.

When encryption is enabled:

- Blob storage expects preferred sequencer batch blobs to be encrypted batch wrappers.
- It decrypts the encrypted transaction bytes with the configured static key.
- It deserializes the transaction vector.
- It constructs `PreferredBatchData` and continues through the existing batch selection and execution path.

Malformed encrypted batches should integrate with existing malformed preferred blob handling:

- Invalid encrypted batch wrapper: reject and slash where existing preferred batch deserialization would slash.
- Decryption failure: reject as malformed preferred sequencer data and slash where appropriate.
- Decrypted transaction deserialization failure: reject as malformed preferred sequencer data and slash where appropriate.

The implementation should avoid silently skipping preferred encrypted batches without using the established error/slashing path.

### Config

Use one config location for the production feature.

Preferred shape:

```toml
[batch_encryption]
type = "static"
encryption_key = "64_hex_chars"
```

This can live under the rollup config section that is most natural after inspecting current config conventions. The implementation plan should choose exactly one location and remove ambiguous dual config between `stf.encryption` and `sequencer.batch_encryption`.

Startup validation rules:

- If encryption is configured, create one shared encryption layer.
- If the key is malformed, fail startup.
- If the key is missing, fail startup.
- If separate sequencer/STF encryption configs remain for compatibility during migration, they must be equal or startup must fail. The preferred final state is one config field.

### Native and ZK Boundaries

Production support is native full-node support only.

ZK/prover behavior:

- Guest STFs continue to instantiate with no encryption layer.
- Documentation must state that encrypted batch proving is not supported in this phase.
- Feature gates should keep encryption dependencies out of guest builds when practical.
- If existing crate dependency structure makes complete exclusion too large for this pass, it is acceptable for no-default guest checks to compile as long as encrypted proving is explicitly unsupported.

### Security Requirements

- Do not log raw key material.
- Do not include key material in debug output.
- Do not accept all-zero keys.
- Use random nonces for AES-GCM encryption.
- Validate ciphertext length before decryption.
- Treat decrypt failure as authentication failure.
- Keep key material wrapped in a secret-aware type where practical.

### Future KMS Expansion

The future KMS path should be able to replace the static provider behind the same encryption-layer boundary.

Likely future additions:

- `KeyProviderConfig::Kms { ... }`.
- Authenticated key retrieval.
- Key refresh or rotation policy.
- Key ID in encrypted batch metadata.
- Restart/replay strategy for historical keys.

This phase should not implement those behaviors. It should only avoid baking static config directly into sequencer and STF call sites.

## Testing Strategy

### Unit Tests

`sov-encryption`:

- Valid static key is accepted.
- Invalid hex key is rejected.
- Short key is rejected.
- Long key is rejected.
- All-zero key is rejected.
- Key debug output redacts the key.
- AES round-trip succeeds.
- Wrong key fails.
- Truncated ciphertext fails.
- Corrupted ciphertext fails.
- Empty plaintext round-trip succeeds.

### Integration Tests

Sequencer/blob sender:

- Unencrypted path emits `PreferredBatchData`.
- Encrypted path emits encrypted wrapper and does not expose plaintext transactions in serialized blob bytes.
- Encrypted batch decrypts back to the original transaction vector.
- Recovery publication uses the encrypted path.

Blob storage/STF:

- Encrypted preferred batch is selected and converted back to `PreferredBatchData`.
- Invalid encrypted wrapper follows malformed preferred blob handling.
- Decrypt failure follows malformed preferred blob handling.
- Decrypted invalid transaction bytes follow malformed preferred blob handling.
- Unencrypted mode remains backward-compatible.

Config:

- Config without encryption continues to parse.
- Config with valid static encryption parses and starts.
- Config with invalid key fails startup.
- Config snapshots are updated intentionally.

### Verification Gates

Targeted local gates:

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption --all-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer preferred_blob_sender
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-blob-storage
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-sequencer -p sov-blob-storage -p sov-modules-stf-blueprint --all-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-stf-blueprint --no-default-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-blob-storage --no-default-features
```

Final gates before PR update:

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make lint
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make test
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make check-features
```

## Implementation Phases

1. Rebase PR #2 onto current `dev-sync` and resolve conflicts without changing feature behavior.
2. Simplify `sov-encryption` to static-key provider plus future-proof key-provider boundary.
3. Replace queue/key-id/fallback decrypt logic with single-key encrypt/decrypt.
4. Normalize config to one production config location.
5. Update sequencer construction and `PreferredBlobSender` to use the simplified layer.
6. Update STF/blob-storage construction and decrypt error handling.
7. Remove out-of-scope Unix socket and key rotation code.
8. Add and update tests.
9. Update docs and config examples.
10. Run targeted verification and final gates.

## Open Operational Notes

- CLA failure on PR #2 is external to code quality: GitHub reported `cla/signatures` missing and committers needing CLA signatures.
- Historical CI test failure was dominated by `sov-db` flaky/timeout behavior and trybuild timeouts, not by encryption compile failures.
- Current `dev-sync` includes upstream sequencer changes that must be preserved, including `all_proofs_and_completed_blobs()` and runtime DA signer checks.

## Self-Review

- Placeholder scan: no placeholders remain.
- Scope check: the design covers one production feature, native static-key batch encryption, and excludes ZK/KMS implementation.
- Ambiguity check: key rotation, Unix sockets, and ZK proving are explicitly out of scope.
- Type consistency: the design consistently uses one static key provider behind an encryption-layer boundary.

## Implementation Note

The implemented production path uses the root `[batch_encryption]` rollup config section with a static AES-256-GCM key. The encrypted DA wrapper carries sequencing metadata plus ciphertext, but not plaintext transactions or transaction hashes. `execute`/`prove` prover modes fail fast when batch encryption is configured; encrypted proving and live key management remain explicitly out of scope for this phase.
