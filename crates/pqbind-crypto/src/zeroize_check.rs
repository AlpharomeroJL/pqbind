// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
// Copyright (c) 2026 VaultScribe Limited Liability Company

//! Responsibility: Prove at the type level that every secret-bearing state this crate keeps, builds or returns wipes itself on drop.
//!
//! The primitive crates wipe their state only when built with their `zeroize` features (set in this crate's `Cargo.toml`);
//! without them the types drop key schedules and chaining values unwiped, silently. These checks are trait bounds, so a
//! missing feature is a compile error, not a runtime surprise.
//!
//! - **Bindings in the modules that hold the state.** Each module's tests pass the real field or return value to
//!   [`wipes_on_drop`]: the inner Ed25519 key (`sign`), the inner ML-DSA key (`mldsa`) and both halves of a hybrid key (`hybrid`).
//! - **The dependency checks below**, for what the bindings rest on: the parts of HMAC and HKDF. `hmac` 0.13 and `hkdf` 0.13
//!   put no `ZeroizeOnDrop` on their own types, so the check is on their parts (the SHA-2 chaining states and the block buffer,
//!   which carry the marker), and size pins fail to compile if either crate adds a field.
//!
//! No memory probe reads bytes after a drop: that needs `unsafe`, which this crate does not use.

use hkdf::Hkdf;
use hkdf::hmac::block_api::HmacCore;
use hkdf::hmac::digest::CtOutput;
use hkdf::hmac::digest::block_api::Buffer;
use hkdf::hmac::{EagerHash, Hmac};
use sha2::Sha384;
use zeroize::ZeroizeOnDrop;

/// Compiles only for a type that wipes itself on drop.
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// Compiles only when the type of `value` wipes itself on drop. Modules pass their real fields and return values, so the check
/// is bound to the type the code holds rather than to a type named here.
pub(crate) fn wipes_on_drop<T: ZeroizeOnDrop>(_value: &T) {}

// Shape pins. `Hmac<D>` is `HmacCore<D>` (the inner and outer chaining states, two `D::Core`) followed by one block buffer
// (hmac 0.13.0 `block_api.rs`, digest 0.11.3 `buffer_macros/fixed.rs`), and `Hkdf<D>` is one `Hmac<D>` (hkdf 0.13.0). If an
// upstream release adds a field, these stop compiling and the parts below must be checked again.
const _: () = assert!(size_of::<HmacCore<Sha384>>() == 2 * size_of::<<Sha384 as EagerHash>::Core>());
const _: () = assert!(size_of::<Hmac<Sha384>>() == size_of::<HmacCore<Sha384>>() + size_of::<Buffer<HmacCore<Sha384>>>());
const _: () = assert!(size_of::<Hkdf<Sha384>>() == size_of::<Hmac<Sha384>>());

#[test]
fn hmac_and_hkdf_states_wipe_their_parts_on_drop() {
    // HMAC-SHA-384 (HKDF-SHA384): the two SHA-384 chaining states, after K^ipad and K^opad, which are as good as the key, and the
    // pending block.
    assert_zeroize_on_drop::<<Sha384 as EagerHash>::Core>();
    assert_zeroize_on_drop::<Buffer<HmacCore<Sha384>>>();
    assert_zeroize_on_drop::<Sha384>();
    // The finalized MAC value.
    assert_zeroize_on_drop::<CtOutput<Hmac<Sha384>>>();
}
