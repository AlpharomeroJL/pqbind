#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
# Copyright (c) 2026 VaultScribe Limited Liability Company
# The local gate: the checks, in order, stopping at the first failure. Run from anywhere.
set -u
cd "$(dirname "$0")/.." || exit 1

run() {
  name=$1
  shift
  echo "== $name"
  if ! "$@"; then
    echo "FAILED: $name" >&2
    exit 1
  fi
}

reuse_check() {
  if command -v reuse >/dev/null 2>&1; then reuse lint; else python3 -I scripts/reuse_check.py; fi
}

run "fmt" cargo fmt --all --check
run "clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings
run "test" cargo test --workspace --all-features
run "deny" cargo deny check
RUSTDOCFLAGS="-D warnings" run "doc" cargo doc --workspace --no-deps --all-features
run "reuse" reuse_check
echo "All checks passed."
