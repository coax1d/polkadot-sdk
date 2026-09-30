pub use pallet::*;

use alloc::vec::Vec;

use frame_support::traits::OneSessionHandler;
use sp_runtime::BoundToRuntimeAppPublic;

/// Session handler for the BEEFY session key in runtimes without `pallet_beefy`.
///
/// The DKG reuses the validators' BEEFY (ECDSA,BLS12-381) session keys
/// (decision: Alistair, 2026-09-29). This handler is a no-op for now: the DKG
/// gadget reads the validator keys from the session pallet's `QueuedKeys`
/// storage directly. Session notifications get wired up once the worker loop
/// manages DKG rounds across key rotations.
pub struct BeefySessionHandler;

impl BoundToRuntimeAppPublic for BeefySessionHandler {
	type Public = sp_consensus_beefy::ecdsa_bls_crypto::AuthorityId;
}

impl<ValidatorId> OneSessionHandler<ValidatorId> for BeefySessionHandler {
	type Key = sp_consensus_beefy::ecdsa_bls_crypto::AuthorityId;

	fn on_genesis_session<'a, I: 'a>(_: I)
	where
		I: Iterator<Item = (&'a ValidatorId, Self::Key)>,
		ValidatorId: 'a,
	{
	}

	fn on_new_session<'a, I: 'a>(_: bool, _: I, _: I)
	where
		I: Iterator<Item = (&'a ValidatorId, Self::Key)>,
		ValidatorId: 'a,
	{
	}

	fn on_disabled(_: u32) {}
}


/// Look up an account's registered BEEFY session key.
///
/// Implemented by the runtime; backed by the session pallet's queued keys when the
/// runtime has one. The `()` impl models "no session pallet": nobody is a validator.
pub trait DkgKeyLookup<AccountId> {
	/// The account's registered BEEFY session key, or `None` if `who` is not a
	/// (queued) validator or has no BEEFY key registered.
	fn dkg_key(who: &AccountId) -> Option<Vec<u8>>;
}

impl<AccountId> DkgKeyLookup<AccountId> for () {
	fn dkg_key(_: &AccountId) -> Option<Vec<u8>> {
		None
	}
}

/// Serialized size of the ECDSA component of a BEEFY paired public key.
const ECDSA_SIZE: usize = 33;
/// Serialized size of the G2 component of a (double) BLS12-381 public key.
const G2_COMPRESSED_SIZE: usize = 96;
/// Serialized size of the G1 component of a (double) BLS12-381 public key.
const G1_COMPRESSED_SIZE: usize = 48;

/// Returns the G1 component (the a-DKG dealer key) of a serialized BEEFY paired
/// (ECDSA,BLS12-381) session key, i.e. `raw[129..177]` of the layout
/// `[ecdsa (33B) || pk_in_G2 (96B) || pk_in_G1 (48B)]`
/// (paired key over w3f-bls `DoublePublicKey`).
pub fn session_key_g1(raw: &[u8]) -> Option<&[u8]> {
	raw.get(ECDSA_SIZE + G2_COMPRESSED_SIZE..ECDSA_SIZE + G2_COMPRESSED_SIZE + G1_COMPRESSED_SIZE)
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use alloc::vec::Vec;

	use adkg_vrf::bls::threshold::ThresholdVk;
	use adkg_vrf::dkg::{transcript::Transcript, Dkg};
	use ark_bls12_381::Bls12_381;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

	use super::{session_key_g1, DkgKeyLookup};

	type DkgTranscript = Transcript<Bls12_381>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Look up the registered BEEFY session key of a validator account, if any.
		type DkgKeyOf: DkgKeyLookup<Self::AccountId>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A valid transcript was merged into the aggregate.
		TranscriptAdded { who: T::AccountId },
		/// The threshold verification key was computed; `c` is the group public key.
		VkComputed { who: T::AccountId, c: Vec<u8> },
	}

	#[pallet::error]
	pub enum Error<T> {
		VerificationFailed,
		DeserializationFailed,
		SerializationFailed,
		NoAggregatedTranscript,
		/// The origin is not a queued validator with a registered BEEFY session key.
		NotAValidator,
		/// The transcript has no contribution receipts.
		NoDealers,
		/// The transcript must come from a single dealer, dealing with the
		/// submitter's own BEEFY session key.
		NotSingleDealer,
		/// The transcript's dealer key does not match the submitter's BEEFY session key.
		UnknownDealer,
	}

	#[pallet::storage]
	#[pallet::getter(fn aggregated_transcript)]
	pub type AggregatedTranscript<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Submit a dealing transcript; it is verified and merged into the aggregate.
		///
		/// Only queued validators can submit, and the transcript must be a fresh
		/// (single-dealer) dealing created with the submitter's own BEEFY session key:
		/// the `ContributionReceipt` proof of possession binds the dealer key, which
		/// must equal the G1 component of the submitter's BEEFY paired key. Aggregation
		/// of multiple dealings happens on-chain via this pallet's own merge logic.
		#[pallet::call_index(0)]
		#[pallet::weight(10_000_000)] // TODO: benchmark
		pub fn add_transcript(origin: OriginFor<T>, transcript_bytes: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let session_key = T::DkgKeyOf::dkg_key(&who).ok_or(Error::<T>::NotAValidator)?;
			let session_g1 = session_key_g1(&session_key).ok_or(Error::<T>::NotAValidator)?;

			let new_transcript = DkgTranscript::deserialize_compressed(&transcript_bytes[..])
				.map_err(|_| Error::<T>::DeserializationFailed)?;

			// TODO: full PVSS verification needs deterministic Fiat-Shamir challenges
			// (adkg-vrf `verify_with_fs`); until then only the deterministic checks run.
			for (receipt, _w) in &new_transcript.receipts {
				receipt.verify_all_sigs().map_err(|_| Error::<T>::VerificationFailed)?;
			}
			new_transcript.check_consistency().map_err(|_| Error::<T>::VerificationFailed)?;

			// Bind the dealing to the submitter: it must be a fresh, single-dealer
			// transcript whose dealer key is the G1 component of the submitter's
			// BEEFY paired session key.
			let dealers = new_transcript.list_dealers();
			let dealer_pk = dealers.first().ok_or(Error::<T>::NoDealers)?;
			ensure!(dealers.iter().all(|d| d == dealer_pk), Error::<T>::NotSingleDealer);
			let mut dealer_bytes = Vec::new();
			dealer_pk
				.serialize_compressed(&mut dealer_bytes)
				.map_err(|_| Error::<T>::SerializationFailed)?;
			ensure!(dealer_bytes == session_g1, Error::<T>::UnknownDealer);

			let aggregated = if let Some(existing_bytes) = AggregatedTranscript::<T>::get() {
				let existing = DkgTranscript::deserialize_compressed(&existing_bytes[..])
					.map_err(|_| Error::<T>::DeserializationFailed)?;
				Dkg::<Bls12_381>::aggregate(alloc::vec![existing, new_transcript])
			} else {
				new_transcript
			};

			let mut aggregated_bytes = Vec::new();
			aggregated
				.serialize_compressed(&mut aggregated_bytes)
				.map_err(|_| Error::<T>::SerializationFailed)?;
			AggregatedTranscript::<T>::put(aggregated_bytes);

			Self::deposit_event(Event::TranscriptAdded { who });
			Ok(())
		}

		/// Compute the threshold verification key from the aggregated transcript.
		#[pallet::call_index(1)]
		#[pallet::weight(10_000_000)] // TODO: benchmark
		pub fn compute_vk(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let transcript_bytes =
				AggregatedTranscript::<T>::get().ok_or(Error::<T>::NoAggregatedTranscript)?;
			let agg_transcript = DkgTranscript::deserialize_compressed(&transcript_bytes[..])
				.map_err(|_| Error::<T>::DeserializationFailed)?;

			// TODO: store/expose the full VK once `ThresholdVk` is serializable.
			let _threshold_vk = ThresholdVk::from_share(&agg_transcript.agg_ss.payload);

			// The group public key `c = f(0).g1` is the VUF verification key.
			let mut c_bytes = Vec::new();
			agg_transcript
				.agg_ss
				.payload
				.c
				.serialize_compressed(&mut c_bytes)
				.map_err(|_| Error::<T>::SerializationFailed)?;

			Self::deposit_event(Event::VkComputed { who, c: c_bytes });
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Projective};
	use ark_ec::{CurveGroup, PrimeGroup};
	use ark_serialize::CanonicalSerialize;

	/// Builds a serialized BEEFY paired key `[ecdsa (33B) || pk_G2 (96B) || pk_G1 (48B)]`
	/// for the given BLS secret, as stored in the session key store. The ECDSA
	/// component is opaque filler (irrelevant to the DKG).
	fn paired_key_bytes(sk: Fr) -> Vec<u8> {
		let pk_g1: G1Affine = (G1Projective::generator() * sk).into_affine();
		let pk_g2: ark_bls12_381::G2Affine = (G2Projective::generator() * sk).into_affine();
		let mut raw = vec![7u8; 33];
		pk_g2.serialize_compressed(&mut raw).unwrap();
		pk_g1.serialize_compressed(&mut raw).unwrap();
		raw
	}

	#[test]
	fn session_key_g1_extracts_dealer_key() {
		let sk = Fr::from(42u64);
		let raw = paired_key_bytes(sk);
		assert_eq!(raw.len(), 177);

		let g1 = session_key_g1(&raw).unwrap();
		let dealer_pk: G1Affine = (G1Projective::generator() * sk).into_affine();
		let mut dealer_bytes = Vec::new();
		dealer_pk.serialize_compressed(&mut dealer_bytes).unwrap();

		// The G1 component of the BEEFY paired key is exactly the a-DKG dealer key.
		assert_eq!(g1, &dealer_bytes[..]);
	}

	#[test]
	fn session_key_g1_rejects_short_keys() {
		assert!(session_key_g1(&[0u8; 176]).is_none());
		assert!(session_key_g1(&[]).is_none());
	}
}
