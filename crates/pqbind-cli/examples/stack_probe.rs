// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Measure how much stack one hybrid signature operation needs, by running it alone on a thread with a stack of a chosen size.
//!
//! A development helper, not a product command. `stack_probe <operation> <KiB>` runs the operation on a thread with exactly that stack. A
//! stack that is too small makes the process die with a stack overflow, so the exit code tells a size that works from one that does not.
//! The operations are the building blocks of the handshake: `from_seed` (expand a key), `verifying_key`, `sign` and `verify` for the
//! ML-DSA-87 half alone, and `hybrid_sign` and `hybrid_verify` for both halves. `sizes` prints how large the key and signature values
//! are, which is what a debug build copies when it moves them.

use std::process::ExitCode;
use std::thread;

use pqbind_crypto::hybrid::{HybridSigningKey, SEED_LEN};
use pqbind_crypto::mldsa::MlDsaSigningKey;

/// The stack of the thread that prepares the inputs, large enough that preparing them never overflows.
const SETUP_STACK_BYTES: usize = 64 * 1024 * 1024;

/// What every operation signs or verifies.
const MESSAGE: &[u8] = b"stack probe message";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(operation), kib) = (args.next(), args.next().and_then(|text| text.parse::<usize>().ok())) else {
        eprintln!("usage: stack_probe <sizes|from_seed|verifying_key|sign|verify|hybrid_sign|hybrid_verify> <stack KiB>");
        return ExitCode::from(2);
    };
    if operation == "sizes" {
        print_sizes();
        return ExitCode::SUCCESS;
    }
    let Some(kib) = kib else {
        eprintln!("stack_probe: the second argument is the stack size in KiB");
        return ExitCode::from(2);
    };
    match run(&operation, kib * 1024) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("stack_probe: {message}");
            ExitCode::from(1)
        }
    }
}

fn print_sizes() {
    println!("MlDsaSigningKey      {} bytes", size_of::<MlDsaSigningKey>());
    println!("HybridSigningKey     {} bytes", size_of::<HybridSigningKey>());
}

/// Run `work` on a thread with `bytes` of stack.
fn on_stack<T: Send + 'static>(bytes: usize, work: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    let handle = thread::Builder::new().stack_size(bytes).spawn(work).map_err(|error| format!("cannot start a thread: {error}"))?;
    handle.join().map_err(|_| "the thread panicked".to_owned())
}

fn run(operation: &str, bytes: usize) -> Result<(), String> {
    // Everything the operation needs is made first, on a large stack, so only the operation itself is measured.
    let (hybrid, public, signature, ml_dsa, ml_public, ml_signature) = on_stack(SETUP_STACK_BYTES, || {
        let hybrid = HybridSigningKey::from_seed(&[7_u8; SEED_LEN]).map_err(|error| error.to_string())?;
        let public = hybrid.verifying_key();
        let signature = hybrid.sign(MESSAGE).map_err(|error| error.to_string())?;
        let ml_dsa = MlDsaSigningKey::from_seed(&[9_u8; 32]);
        let ml_public = ml_dsa.verifying_key();
        let ml_signature = ml_dsa.sign(MESSAGE).map_err(|error| error.to_string())?;
        Ok::<_, String>((hybrid, public, signature, ml_dsa, ml_public, ml_signature))
    })??;

    let done = match operation {
        "from_seed" => on_stack(bytes, move || MlDsaSigningKey::from_seed(&[9_u8; 32]).verifying_key().to_bytes().len())?,
        "verifying_key" => on_stack(bytes, move || ml_dsa.verifying_key().to_bytes().len())?,
        "sign" => on_stack(bytes, move || ml_dsa.sign(MESSAGE).map(|signature| signature.as_bytes().len()).unwrap_or(0))?,
        "verify" => on_stack(bytes, move || usize::from(ml_public.verify(MESSAGE, &ml_signature).is_ok()))?,
        "hybrid_sign" => on_stack(bytes, move || hybrid.sign(MESSAGE).map(|signature| signature.to_bytes().len()).unwrap_or(0))?,
        "hybrid_verify" => on_stack(bytes, move || usize::from(public.verify(MESSAGE, &signature).is_ok()))?,
        other => return Err(format!("unknown operation {other:?}")),
    };
    if done == 0 {
        return Err("the operation did not produce a result".to_owned());
    }
    Ok(())
}
