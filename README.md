# Verkle Differential Auditor — by lau90eth

Differential cryptographic testing across Ethereum Verkle tree implementations (Go, Rust, TypeScript).

## Why

Ethereum's Hegotá hardfork (H2 2026) replaces Merkle Patricia Tries with Verkle trees. A single cryptographic inconsistency between client implementations (Geth, Nethermind, Reth) can fork the chain or corrupt state.

## Goal

Feed identical random key-value vectors to multiple Verkle implementations and detect divergence in:
- Root commitment
- Proof generation/verification
- Witness serialization

## Targets

- [go-verkle](https://github.com/crate-crypto/go-verkle) (Geth / Ethereum Foundation)
- [rust-verkle](https://github.com/crate-crypto/rust-verkle) (Reth / Paradigm)
- TS-Verkle (on-chain verifier research)

## Run

```bash
go run diff_test.go
Author
@lau90eth
