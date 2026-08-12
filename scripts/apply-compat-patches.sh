#!/usr/bin/env bash
# Soften frozen 2021 arkworks crates so they compile on modern rustc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 << 'PY'
from pathlib import Path
import re

for p in Path("third_party").rglob("*.rs"):
    try:
        t = p.read_text()
    except Exception:
        continue
    orig = t
    for name in ("private_in_public", "const_err"):
        t = re.sub(rf",\s*{name}\b", "", t)
        t = re.sub(rf"\b{name}\s*,\s*", "", t)
    if t != orig:
        p.write_text(t)

for p in Path("third_party").rglob("lib.rs"):
    t = p.read_text()
    orig = t
    t = t.replace("#![deny(warnings)]", "#![allow(warnings)]")
    t = re.sub(r"#!\[deny\(\s*warnings\s*,", "#![allow(warnings,", t)
    t = re.sub(r"#!\[deny\(\s*unused\s*,", "#![allow(unused,", t)
    t = re.sub(
        r"#!\[deny\(([^]]*\bwarnings\b[^]]*)\)\]",
        lambda m: "#![allow(" + m.group(1) + ")]",
        t,
    )
    if t != orig:
        p.write_text(t)

p = Path("third_party/r1cs-std/src/bits/uint.rs")
if p.exists():
    t = p.read_text()
    old = '                #[doc($native_doc_name)]\n                #[doc("`.")]'
    new = '                #[doc = $native_doc_name]\n                #[doc = "`.`"]'
    if old in t:
        p.write_text(t.replace(old, new))

# poly-commit: BatchLCProof Clone bound for modern rustc
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

print("compat patches applied")
PY
