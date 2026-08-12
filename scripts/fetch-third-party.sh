#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p third_party

clone_at() {
  local name=$1 url=$2 rev=$3
  if [[ -d "third_party/$name/.git" ]]; then
    git -C "third_party/$name" fetch --all --tags
    git -C "third_party/$name" checkout -f "$rev"
  else
    rm -rf "third_party/$name"
    git clone "$url" "third_party/$name"
    git -C "third_party/$name" checkout -f "$rev"
  fi
  echo "OK $name @ $(git -C "third_party/$name" rev-parse HEAD)"
}

while read -r name rev comment; do
  [[ -z "${name:-}" || "$name" =~ ^# ]] && continue
  case "$name" in
    algebra) url=https://github.com/arkworks-rs/algebra ;;
    utils) url=https://github.com/arkworks-rs/utils ;;
    snark) url=https://github.com/arkworks-rs/snark ;;
    crypto-primitives) url=https://github.com/arkworks-rs/crypto-primitives ;;
    r1cs-std) url=https://github.com/arkworks-rs/r1cs-std ;;
    nonnative) url=https://github.com/arkworks-rs/nonnative ;;
    curves) url=https://github.com/arkworks-rs/curves ;;
    groth16) url=https://github.com/arkworks-rs/groth16 ;;
    gm17) url=https://github.com/arkworks-rs/gm17 ;;
    marlin) url=https://github.com/arkworks-rs/marlin ;;
    poly-commit) url=https://github.com/arkworks-rs/poly-commit ;;
    pcd) url=https://github.com/arkworks-rs/pcd ;;
    *) echo "unknown $name"; exit 1 ;;
  esac
  clone_at "$name" "$url" "$rev"
done < <(grep -v '^#' third_party/REVS.txt | grep -v '^$')

"$ROOT/scripts/apply-compat-patches.sh"
