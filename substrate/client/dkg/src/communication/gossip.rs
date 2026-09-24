use crate::{
	communication::{benefit, cost, peers::KnownPeers, notification::Dealing},
    LOG_TARGET,
};

use sp_runtime::traits::Hash;

use std::{fmt::Display, marker::PhantomData, sync::Arc, time::Duration};

use sp_application_crypto::{AppPublic, RuntimeAppPublic};

use codec::{Encode, Decode, DecodeWithMemTracking};
use scale_info::TypeInfo;

use sc_network::{NetworkPeers, ReputationChange};

use parking_lot::{Mutex, RwLock};
use wasm_timer::Instant;

const REBROADCAST_AFTER: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq)]
pub(super) enum Action<H> {
	// repropagate under given topic, to the given peers, applying cost/benefit to originator.
	Keep(H, ReputationChange),
	// discard, applying cost/benefit to originator.
	Discard(ReputationChange),
	// ignore, no cost/benefit applied to originator.
	DiscardNoReport,
}

/// An outcome of examining a message.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Consider {
	/// Accept the message.
	Accept,
	/// Message cannot be evaluated. Reject.
	CannotEvaluate,
}

/// DKG Dealing Message.
///
/// A Dealing message is the dealing of a single participant in our DKG scheme with a signature attached
#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, PartialEq, TypeInfo)]
pub struct DealingMessage<Dealing, Id, Signature> {
	/// Commit to information extracted from a finalized block
	pub dealing: Dealing,
    /// Node authority id
	pub id: Id,
	/// Node signature
	pub signature: Signature,
}

/// DKG gossip message type that gets encoded and sent on the network.
#[derive(Debug, Encode, Decode)]
pub(crate) enum GossipMessage<AuthorityId: AuthorityIdBound> {
	/// DKG message with commitment and single signature.
	Dealing(DealingMessage<Dealing<Vec<u8>>, AuthorityId, <AuthorityId as RuntimeAppPublic>::Signature>),
    // TODO: Add another message?
    Temp,
}

pub trait AuthorityIdBound:
    Ord
	+ AppPublic
    + Display
    + RuntimeAppPublic
{

}

impl<AuthorityId: AuthorityIdBound> GossipMessage<AuthorityId> {
    pub fn unwrap_dealing(
        self
    ) -> Option<DealingMessage<Dealing<Vec<u8>>, AuthorityId, <AuthorityId as RuntimeAppPublic>::Signature>> {
        match self {
            GossipMessage::Dealing(dealing) => Some(dealing),
            GossipMessage::Temp => None,
        }
    }
}

/// Gossip engine dealings messages topic
pub(crate) fn dealings_topic<H: Hash>() -> H::Output
where
	H: Hash,
{
	H::hash_of(b"dkg-dealing")
}

// TODO: Put this in a primitives crate for DKG, similar to `sp-consensus-beefy`.
/// DKG cryptographic types for BLS12-381 crypto.
///
/// Uses substrate's experimental BLS12-381 scheme (w3f-bls): the public key is a
/// `DoublePublicKey` = `[pk_in_G2 (96B) || pk_in_G1 (48B)]`. The G2 component is the
/// validator's signer public key in the a-DKG (`adkg-vrf`).
///
/// This module basically introduces four crypto types:
/// - `bls_crypto::Pair`
/// - `bls_crypto::Public`
/// - `bls_crypto::Signature`
/// - `bls_crypto::AuthorityId`
///
/// Your code should use the above types as concrete types for all crypto related
/// functionality.
#[cfg(feature = "bls-experimental")]
pub mod bls_crypto {
	use super::AuthorityIdBound;
	use sp_application_crypto::{app_crypto, bls381};

	// TODO: Put this in Keytypes module in crypto similar to babe beefy etc..
    // sp_application_crypto::key_types
    /// Key type for DKG module.
	pub const DKG: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"dkgg");

	app_crypto!(bls381, DKG);

	/// Identity of a DKG authority using BLS12-381 as its crypto.
	pub type AuthorityId = Public;

	/// Signature for a DKG authority using BLS12-381 as its crypto.
	pub type AuthoritySignature = Signature;

	impl AuthorityIdBound for AuthorityId {

	}

	/// Serialized size of the G2 component of a (double) BLS12-381 public key.
	const G2_COMPRESSED_SIZE: usize = 96;

	/// Extracts the G2 component of a validator's (double) BLS12-381 public key,
	/// i.e. the signer public key used by the a-DKG (`adkg-vrf`).
	///
	/// Layout: `[pk_in_G2 (96B) || pk_in_G1 (48B)]`, see `w3f-bls` `DoublePublicKey`.
	pub fn to_ark_g2(public: &Public) -> Option<ark_bls12_381::G2Affine> {
		use ark_serialize::CanonicalDeserialize;
		let bytes: &[u8] = AsRef::<[u8]>::as_ref(public);
		ark_bls12_381::G2Affine::deserialize_compressed(&bytes[..G2_COMPRESSED_SIZE]).ok()
	}

	/// Returns all DKG BLS12-381 public keys stored in the keystore.
	pub fn public_keys(store: &sp_keystore::KeystorePtr) -> Vec<Public> {
		use sp_core::crypto::ByteArray;
		store
			.bls381_public_keys(DKG)
			.into_iter()
			.filter_map(|p| Public::from_slice(p.as_ref()).ok())
			.collect()
	}

	/// Signs a DKG dealing message with the validator's BLS12-381 key from the keystore.
	/// Returns `Ok(None)` if the key is not in the keystore.
	pub fn sign_with_store(
		store: &sp_keystore::KeystorePtr,
		public: &Public,
		msg: &[u8],
	) -> Result<Option<Signature>, sp_keystore::Error> {
		use sp_core::crypto::ByteArray;
		let raw_public = sp_core::bls381::Public::from_slice(AsRef::<[u8]>::as_ref(public))
			.map_err(|_| sp_keystore::Error::ValidationError("invalid DKG public key".into()))?;
		let sig = store.bls381_sign(DKG, &raw_public, msg)?;
		Ok(sig.and_then(|s| Signature::from_slice(s.as_ref()).ok()))
	}
}


// TODO: Add Gossip Filters ? Which to Add?

pub struct Filter<AuthorityId>(PhantomData<AuthorityId>);


/// DKG gossip validator
///
/// Validate DKG gossip messages and produce dealings.
pub(crate) struct GossipValidator<H, N, AuthorityId: AuthorityIdBound>
where
    H: Hash
{
	dealings_topic: H,
	gossip_filter: RwLock<Filter<AuthorityId>>,
	next_rebroadcast: Mutex<Instant>,
	known_peers: Arc<Mutex<KnownPeers<H>>>,
	network: Arc<N>,
}
#[cfg(all(test, feature = "bls-experimental"))]
mod tests {
	use super::bls_crypto;
	use ark_bls12_381::{Fr, G1Projective, G2Projective};
	use ark_ec::{CurveGroup, PrimeGroup};
	use ark_ff::UniformRand;
	use ark_serialize::CanonicalSerialize;
	use sp_core::crypto::UncheckedFrom;

	/// The `DoublePublicKey` layout is `[pk_in_G2 (96B) || pk_in_G1 (48B)]`;
	/// `to_ark_g2` must extract exactly the G2 component used by the a-DKG.
	#[test]
	fn ark_g2_extraction_matches_double_public_key_layout() {
		let rng = &mut ark_std::test_rng();
		let sk = Fr::rand(rng);
		let pk_g1 = (G1Projective::generator() * sk).into_affine();
		let pk_g2 = (G2Projective::generator() * sk).into_affine();

		let mut raw = [0u8; 144];
		pk_g2.serialize_compressed(&mut raw[..96]).unwrap();
		pk_g1.serialize_compressed(&mut raw[96..]).unwrap();

		let public = bls_crypto::Public::unchecked_from(raw);
		assert_eq!(bls_crypto::to_ark_g2(&public), Some(pk_g2));
	}
}
