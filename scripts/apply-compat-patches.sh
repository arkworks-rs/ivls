#!/usr/bin/env bash
# Soften frozen 2021 arkworks crates so they compile on modern rustc
# without needing RUSTFLAGS (which breaks bare-metal target probes).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 << 'PY'
from pathlib import Path
import re

def soften_crate_lints(text: str) -> str:
    # Drop removed lint names that modern rustc rejects.
    for name in ("private_in_public", "const_err"):
        text = re.sub(rf",\s*{name}\b", "", text)
        text = re.sub(rf"\b{name}\s*,\s*", "", text)

    # Convert crate-level #![deny(...)] to #![allow(...)], except unsafe_code.
    def repl_deny(m: re.Match) -> str:
        body = m.group(1)
        if re.search(r"\bunsafe_code\b", body):
            return m.group(0)
        return "#![allow(" + body + ")]"

    text = re.sub(r"#!\[deny\((.*?)\)\]", repl_deny, text, flags=re.S)

    # Same for #![warn(...)] that modern rustc escalates awkwardly in deps.
    def repl_warn(m: re.Match) -> str:
        body = m.group(1)
        if re.search(r"\bunsafe_code\b", body):
            return m.group(0)
        return "#![allow(" + body + ")]"

    text = re.sub(r"#!\[warn\((.*?)\)\]", repl_warn, text, flags=re.S)
    return text


for p in Path("third_party").rglob("*.rs"):
    try:
        orig = p.read_text()
    except Exception:
        continue
    new = soften_crate_lints(orig)
    if new != orig:
        p.write_text(new)

# r1cs-std: invalid doc attribute syntax on modern rustc
p = Path("third_party/r1cs-std/src/bits/uint.rs")
if p.exists():
    t = p.read_text()
    old = '                #[doc($native_doc_name)]\n                #[doc("`.")]'
    new = '                #[doc = $native_doc_name]\n                #[doc = "`.`"]'
    if old in t:
        p.write_text(t.replace(old, new))

# poly-commit: Clone derive bound + never-type fallback
p = Path("third_party/poly-commit/src/data_structures.rs")
if p.exists():
    t = p.read_text()
    t2 = re.sub(
        r"#\[derivative\(Clone\(bound = \"F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>\"\)\)\]",
        '#[derivative(Clone(bound = "PC::BatchProof: Clone"))]',
        t,
    )
    if t2 != t:
        p.write_text(t2)

for p in Path("third_party/poly-commit").rglob("*.rs"):
    t = p.read_text()
    if ".collect::<Result<_, _>>()?" in t:
        p.write_text(t.replace(".collect::<Result<_, _>>()?", ".collect::<Result<(), _>>()?"))

# poly-commit / marlin still reference bench-utils after it moved into utils workspace
pc = Path("third_party/poly-commit/Cargo.toml")
if pc.exists():
    t = pc.read_text()
    if "bench-utils" not in t and 'ark-std = { git = "https://github.com/arkworks-rs/utils"' in t:
        t = t.replace(
            'ark-std = { git = "https://github.com/arkworks-rs/utils", default-features = false }',
            'ark-std = { git = "https://github.com/arkworks-rs/utils", default-features = false }\n'
            'bench-utils = { git = "https://github.com/arkworks-rs/utils", default-features = false }',
        )
        t = t.replace(
            'print-trace = [ "ark-std/print-trace" ]',
            'print-trace = [ "bench-utils/print-trace" ]',
        )
        t = t.replace(
            'print-trace = [ "bench-utils/print-trace" ]',
            'print-trace = [ "bench-utils/print-trace" ]',
        )
        pc.write_text(t)

lib = Path("third_party/poly-commit/src/lib.rs")
if lib.exists():
    t = lib.read_text()
    if "extern crate bench_utils" not in t and "start_timer!" in Path("third_party/poly-commit/src").read_text() if False else True:
        # Ensure macros are available if sources use start_timer!
        needs = any(
            "start_timer!" in q.read_text() or "end_timer!" in q.read_text()
            for q in Path("third_party/poly-commit/src").rglob("*.rs")
        )
        if needs and "extern crate bench_utils" not in t:
            t = t.replace(
                "extern crate derivative;",
                "extern crate derivative;\n#[macro_use]\nextern crate bench_utils;",
            )
            lib.write_text(t)

print("compat patches applied")
PY
