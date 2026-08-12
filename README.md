<h1 align="center">Incrementally Verifiable Ledger Systems (IVLS)</h1>

This arkworks library describes an interface and contains an implementation for incrementally verifiable ledger systems (IVLS).

An IVLS adds additional security properties to a ledger system, which consists of a state, a transition function, and a client function that reads data from the state. (Blockchains and transparency logs are two of the most prominent examples of ledger systems.) In an IVLS, each state is augmented with a proof that it has been achieved through valid transactions, and a succinct commitment relative to which the client function's answers can be proved. All proofs are succinct and can be efficiently verified.

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

The library includes a [circuit-specific setup IVLS compiler](src/compiler/circuit_specific_setup_compiler.rs) and a [universal setup IVLS compiler](src/compiler/universal_setup_compiler.rs). The transition function is built on top of the arkworks PCD library, and the PCD type (which is in turn determined by the underlying SNARK type) determines the type of the IVLS compiler. IVLS is built on top of the Merkle tree implemented [here](src/building_blocks/mt/).

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo`, the standard Rust build tool, to build the libraries:
```bash
git clone https://github.com/arkworks-rs/ivls.git
cd ivls
cargo build
```


## Dependency freeze (archival)

This repository is pinned to the **arkworks ecosystem as of ~2021-02-09** (the last
period when `ark-pcd`, Marlin R1CS constraints, and this crate formed a coherent
graph). Modern arkworks 0.4–0.6 is **not** drop-in compatible.

Build:

```bash
./scripts/fetch-third-party.sh   # clones pinned upstream revs into third_party/
cargo test --test merkle_sparse_tree --test state --test verifiable_transition_mnt_small_groth16
```

- Exact commits: `third_party/REVS.txt`
- `third_party/*/` is gitignored; only the rev list and scripts are tracked
- Builds use `.cargo/config.toml` (`--cap-lints=allow`) so old crates compile on new rustc
- Full integration tests (Marlin / MNT-753) are very slow (tens of minutes to hours)

## Tests
This library comes with comprehensive unit and integration tests. Run the tests with:
```bash
cargo test --all
```

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
