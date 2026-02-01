# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust CLI tool that generates PGP keys deterministically from a 12-word BIP39 seed phrase, enabling PGP key recovery similar to cryptocurrency wallets.

## Build and Test Commands

```bash
cargo build --release          # Build release binary
cargo test --release --verbose # Run tests (as per CI)
cargo install --path .         # Install from source
```

## Architecture

### Key Generation Flow
1. `src/main.rs` - CLI entry point using clap for argument parsing
2. `src/generate.rs` - Core key generation logic:
   - Converts BIP39 mnemonic to seed
   - Uses HKDF-SHA3-256 to derive unique seeds for each key
   - Primary email address is hashed and used as salt for RNG derivation
   - ChaCha20 CSPRNG generates RSA-4096 key material

### Generated Key Structure
- Primary key: RSA-4096 (Certify)
- Subkey 1: RSA-4096 (Sign)
- Subkey 2: RSA-4096 (Encrypt)
- Subkey 3: RSA-4096 (Authenticate)

### OpenPGP Implementation
`src/pgp/` contains an embedded modified version of the `rpgp` crate:
- `composed/key/` - High-level key generation and manipulation
- `crypto/` - Cryptographic primitives (RSA, ECC, hashing, symmetric encryption)
- `packet/` - Low-level PGP packet parsing and generation
- `armor/` - ASCII armor encoding/decoding

## Key Constraints

- **No unsafe code** - The crate forbids unsafe code
- **Determinism stability** - Key generation is only stable within the same minor version (for 0.x releases). Changes affecting key output require version bumps.
- **Strict linting** - Uses comprehensive clippy lints (all, style, perf, complexity, correctness)

## Testing

Tests include stability validation in `src/generate.rs` and external test vectors in `tests/` (OpenPGP interop, autocrypt).
