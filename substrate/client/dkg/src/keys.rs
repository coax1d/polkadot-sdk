//! DKG authority set: the validator accounts and their DKG BLS12-381 session keys.
//!
//! The DKG gadget needs the public keys of all participating validators to build
//! the `adkg-vrf` signer set (`Dkg::new`). These keys are registered on-chain as a
//! session key (key type `dkgg`, see `sp-consensus-dkg`), so the gadget reads them
//! straight from the session pallet's `QueuedKeys` storage item — no dedicated
//! runtime API required. `QueuedKeys` holds the keys of the upcoming session; the
//! worker loop (re)builds the authority set whenever the session rotates.

use std::collections::BTreeMap;

use codec::Decode;
use sc_client_api::{StorageKey, StorageProvider};
use sp_blockchain::Error as BlockchainError;
use sp_consensus_dkg::bls_crypto::{Public, DKG_KEY_TYPE};
use sp_core::crypto::ByteArray;
use sp_crypto_hashing::twox_128;
use sp_runtime::traits::{Block as BlockT, OpaqueKeys};

use thiserror::Error;

/// Error while fetching the DKG authority set from chain state.
#[derive(Debug, Error)]
pub enum AuthoritySetError {
	/// `Session::QueuedKeys` is not present at the given block.
	#[error("Session::QueuedKeys not found at block")]
	MissingQueuedKeys,
	/// `Session::QueuedKeys` failed to SCALE-decode.
	#[error("failed to decode Session::QueuedKeys")]
	DecodeFailed,
	/// No validator has a registered DKG session key.
	#[error("no DKG session keys registered (is the 'dkgg' key in the runtime SessionKeys?)")]
	NoDkgKeys,
	/// Backend error.
	#[error(transparent)]
	Blockchain(#[from] BlockchainError),
}

/// The DKG authority set: validator account id -> DKG public key.
pub type AuthoritySet<AccountId> = BTreeMap<AccountId, Public>;

/// Fetches the queued validators' DKG keys from `Session::QueuedKeys` at `hash`.
///
/// `AccountId` and `Keys` are the runtime's session types, supplied by the caller
/// integrating the gadget (e.g. `cumulus_test_runtime::SessionKeys`). Validators
/// without a registered DKG key are skipped.
pub fn queued_dkg_keys<Client, Block, Backend, AccountId, Keys>(
	client: &Client,
	hash: Block::Hash,
) -> Result<AuthoritySet<AccountId>, AuthoritySetError>
where
	Block: BlockT,
	Backend: sc_client_api::backend::Backend<Block>,
	Client: StorageProvider<Block, Backend>,
	AccountId: Decode + Ord,
	Keys: OpaqueKeys + Decode,
{
	let mut storage_key = twox_128(b"Session").to_vec();
	storage_key.extend_from_slice(&twox_128(b"QueuedKeys"));
	let data = client
		.storage(hash, &StorageKey(storage_key))?
		.ok_or(AuthoritySetError::MissingQueuedKeys)?;

	let queued: Vec<(AccountId, Keys)> =
		Decode::decode(&mut &data.0[..]).map_err(|_| AuthoritySetError::DecodeFailed)?;

	let set: AuthoritySet<AccountId> = queued
		.into_iter()
		.filter_map(|(who, keys)| {
			Public::from_slice(keys.get_raw(DKG_KEY_TYPE))
				.ok()
				.map(|public| (who, public))
		})
		.collect();

	if set.is_empty() {
		return Err(AuthoritySetError::NoDkgKeys)
	}
	Ok(set)
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;

	mod test_aura {
		use sp_application_crypto::{app_crypto, sr25519};
		use sp_core::crypto::KeyTypeId;

		pub const TEST_AURA: KeyTypeId = KeyTypeId(*b"aura");

		app_crypto!(sr25519, TEST_AURA);
	}

	mod test_dkg {
		use sp_application_crypto::{app_crypto, bls381};
		use sp_core::crypto::KeyTypeId;

		pub const TEST_DKG: KeyTypeId = KeyTypeId(*b"dkgg");

		app_crypto!(bls381, TEST_DKG);
	}

	sp_runtime::impl_opaque_keys! {
		pub struct TestSessionKeys {
			pub aura: test_aura::Public,
			pub dkg: test_dkg::Public,
		}
	}

	#[test]
	fn extracts_dkg_key_from_opaque_session_keys() {
		let dkg_raw = [7u8; 144];
		let keys = TestSessionKeys {
			aura: test_aura::Public::from_slice(&[1u8; 32]).unwrap(),
			dkg: test_dkg::Public::from_slice(&dkg_raw).unwrap(),
		};

		// The full struct must round-trip through SCALE (this is how it is stored
		// inside `Session::QueuedKeys`), and the `dkgg` key must land at the right
		// offset, next to the other session keys.
		let encoded = keys.encode();
		let decoded = TestSessionKeys::decode(&mut &encoded[..]).unwrap();

		let extracted = Public::from_slice(decoded.get_raw(DKG_KEY_TYPE)).unwrap();
		assert_eq!(AsRef::<[u8]>::as_ref(&extracted), &dkg_raw[..]);
		// Sanity: the aura key must not collide with the dkg offset.
		assert_eq!(decoded.get_raw(test_aura::TEST_AURA), &[1u8; 32][..]);
	}
}
