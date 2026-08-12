<h1 align="center">Incrementally Verifiable Ledger Systems (IVLS)</h1>

> **Public archive.** This repository is frozen for historical reference. It is
> not under active development and is not intended for production use.

This arkworks library describes an interface and contains a 2020–2021-era
implementation of **incrementally verifiable ledger systems (IVLS)**.

An IVLS adds additional security properties to a ledger system, which consists
of a state, a transition function, and a client function that reads data from
the state. (Blockchains and transparency logs are two of the most prominent
examples of ledger systems.) In an IVLS, each state is augmented with a proof
that it has been achieved through valid transactions, and a succinct commitment
relative to which the client function's answers can be proved. All proofs are
succinct and can be efficiently verified.

## Historical note

Work concurrent with and following this project has substantially developed the
IVLS idea—recursive / incremental proofs over evolving state—and that line of
work has become a central direction for **Ethereum L2** systems and a serious
candidate for **future L1** designs.

The technology stack has also moved on:

- **Circuits** are no longer primarily written in general-purpose constraint
  systems such as **R1CS**. Production systems increasingly use specialized
  circuit structures and DSLs tailored to recursion and rollups.
- **Proof systems** have been shifting toward **hash-based, post-quantum**
  constructions (and related transparent / FRI-style designs). These systems are
  typically much more efficient for the recursive-ledger setting than the
  pairing-based SNARK stack used here.

This repository therefore remains only as a **reference** implementation of an
early academic prototype in the arkworks stack. Prefer current rollup / zkVM /
recursion frameworks for new work.

## Implementation (archived)

The library includes a
[circuit-specific setup IVLS compiler](src/compiler/circuit_specific_setup_compiler.rs)
and a
[universal setup IVLS compiler](src/compiler/universal_setup_compiler.rs).
The transition function is built on top of the arkworks PCD library; the PCD
type (determined by the underlying SNARK) determines the IVLS compiler type.
IVLS is built on top of the Merkle tree implemented
[here](src/building_blocks/mt/).

**WARNING:** This is an academic proof-of-concept prototype. It has not received
careful code review and is **not** ready for production use.

It is released under the MIT License and the Apache v2 License (see
[License](#license)).

## Dependency freeze

This tree is pinned to the **arkworks ecosystem as of ~2021-02-09** (the last
period when `ark-pcd`, Marlin R1CS constraints, and this crate still formed a
coherent graph). Modern arkworks **0.4–0.6 is not drop-in compatible**; APIs,
crate layout, and several upstream repos have since been renamed, archived, or
rewritten.

### Build (reference only)

```bash
git clone https://github.com/arkworks-rs/ivls.git
cd ivls
./scripts/fetch-third-party.sh   # clones pinned upstream revs into third_party/
export RUSTFLAGS=--cap-lints=allow
cargo test --test merkle_sparse_tree --test state --test verifiable_transition_mnt_small_groth16
```

- Exact upstream commits: [`third_party/REVS.txt`](third_party/REVS.txt)
- `third_party/*/` is gitignored; only the rev list and scripts are tracked
- Do **not** put `--cap-lints=allow` in `.cargo/config.toml`; it breaks bare-metal
  target probes used by `no_std` checks
- Full integration tests (Marlin / MNT-753) are very slow (tens of minutes to hours)

Requires a recent stable Rust toolchain. Install via [rustup](https://rustup.rs/)
if needed.

## License

The crates in this repo are licensed under either of the following licenses, at
your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion
in this library by you shall be dual licensed as above (as defined in the Apache
v2 License), without any additional terms or conditions.
