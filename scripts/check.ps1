# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
# Copyright (c) 2026 VaultScribe Limited Liability Company
# The local gate: the checks, in order, stopping at the first failure. Run from anywhere.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)

function Step([string]$Name, [scriptblock]$Command) {
    Write-Host "== $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
}

Step 'fmt' { cargo fmt --all --check }
Step 'clippy' { cargo clippy --workspace --all-targets --all-features -- -D warnings }
Step 'test' { cargo test --workspace --all-features }
Step 'deny' { cargo deny check }
Step 'doc' {
    $env:RUSTDOCFLAGS = '-D warnings'
    cargo doc --workspace --no-deps --all-features
}
Step 'reuse' {
    if (Get-Command reuse -ErrorAction SilentlyContinue) { reuse lint } else { python -I scripts/reuse_check.py }
}
Write-Host 'All checks passed.'
