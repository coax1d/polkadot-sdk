//! Primitives for the DKG (distributed key generation) protocol.
//!
//! The DKG lets the validator set jointly generate a threshold BLS12-381 key
//! (via the `adkg-vrf` PVSS scheme); the resulting threshold verification key
//! is used as a VUF/beacon. Validators participate with a dedicated DKG
//! session key of the substrate experimental BLS12-381 type (`w3f-bls`
//! `DoublePublicKey`), separate from BEEFY keys.
//!
//! The client-side gadget lives in `sc-dkg`.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::crypto::KeyTypeId;

/// Key type for the DKG module.
pub const DKG_KEY_TYPE: KeyTypeId = KeyTypeId(*b"dkgg");

/// DKG cryptographic types for BLS12-381 crypto.
///
/// Uses substrate's experimental BLS12-381 scheme (w3f-bls): the public key is a
/// `DoublePublicKey` = `[pk_in_G2 (96B) || pk_in_G1 (48B)]`. The G2 component is the
/// validator's signer public key in the a-DKG (`adkg-vrf`); the G1 component is the
/// dealer public key bound by the `ContributionReceipt` proof of possession.
///
/// This module introduces four crypto types:
/// - `bls_crypto::Pair`
/// - `bls_crypto::Public`
/// - `bls_crypto::Signature`
/// - `bls_crypto::AuthorityId`
///
/// Your code should use the above types as concrete types for all crypto related
/// functionality.
#[cfg(feature = "bls-experimental")]
pub mod bls_crypto {
	pub use super::DKG_KEY_TYPE;
	use sp_application_crypto::{app_crypto, bls381};

	app_crypto!(bls381, DKG_KEY_TYPE);

	/// Identity of a DKG authority using BLS12-381 as its crypto.
	pub type AuthorityId = Public;

	/// Signature of a DKG authority using BLS12-381 as its crypto.
	pub type AuthoritySignature = Signature;
}
