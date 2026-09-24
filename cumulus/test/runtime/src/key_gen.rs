pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use alloc::vec::Vec;

	use adkg_vrf::bls::threshold::ThresholdVk;
	use adkg_vrf::dkg::{transcript::Transcript, Dkg};
	use ark_bls12_381::Bls12_381;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

	type DkgTranscript = Transcript<Bls12_381>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
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
	}

	#[pallet::storage]
	#[pallet::getter(fn aggregated_transcript)]
	pub type AggregatedTranscript<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Submit a dealing transcript; it is verified and merged into the aggregate.
		#[pallet::call_index(0)]
		#[pallet::weight(10_000_000)] // TODO: benchmark
		pub fn add_transcript(origin: OriginFor<T>, transcript_bytes: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// TODO: restrict the origin to validators/collators.
			let new_transcript = DkgTranscript::deserialize_compressed(&transcript_bytes[..])
				.map_err(|_| Error::<T>::DeserializationFailed)?;

			// TODO: full PVSS verification needs deterministic Fiat-Shamir challenges
			// (adkg-vrf `verify_with_fs`); until then only the deterministic checks run.
			for (receipt, _w) in &new_transcript.receipts {
				receipt.verify_all_sigs().map_err(|_| Error::<T>::VerificationFailed)?;
			}
			new_transcript.check_consistency().map_err(|_| Error::<T>::VerificationFailed)?;

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
