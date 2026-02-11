//! # Shielded Pool Pallet
//!
//! A Zcash-inspired shielded UTXO pool using Pedersen commitments on the Pallas
//! elliptic curve. Provides confidential value transfers with double-spend
//! prevention via nullifiers.
//!
//! ## Overview
//!
//! - **Mint**: Move public balance into the shielded pool by creating a Pedersen
//!   commitment that hides the value.
//! - **Transfer**: Spend shielded notes (publishing nullifiers) and create new
//!   shielded notes. Balance is verified homomorphically without revealing values.
//! - **Burn**: Reveal a commitment to withdraw value back to a public balance.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

pub mod commitment;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use super::commitment;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config:
		frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_balances::Config
	{
	}

	/// Live note commitments. Key is blake2_256(serialized_point).
	#[pallet::storage]
	pub type NoteCommitments<T: Config> =
		StorageMap<_, Blake2_128Concat, [u8; 32], (), OptionQuery>;

	/// Spent nullifiers. A nullifier can only appear once.
	#[pallet::storage]
	pub type Nullifiers<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 32], (), OptionQuery>;

	/// Total value held in the shielded pool (for sanity tracking).
	#[pallet::storage]
	pub type PoolBalance<T: Config> = StorageValue<_, u128, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A note was minted into the shielded pool.
		NoteMinted {
			who: T::AccountId,
			commitment: [u8; 32],
			value: u128,
		},
		/// Shielded notes were transferred (nullifiers spent, new commitments created).
		NoteTransferred {
			nullifiers: Vec<[u8; 32]>,
			new_commitments: Vec<[u8; 32]>,
		},
		/// A note was burned (withdrawn from shielded pool to public balance).
		NoteBurned {
			who: T::AccountId,
			nullifier: [u8; 32],
			value: u128,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The commitment already exists in the pool.
		CommitmentAlreadyExists,
		/// The nullifier has already been spent.
		NullifierAlreadySpent,
		/// The commitment was not found in the pool.
		CommitmentNotFound,
		/// The commitment is not a valid curve point.
		InvalidCommitment,
		/// Input and output values do not balance.
		BalanceMismatch,
		/// Insufficient public balance for minting.
		InsufficientBalance,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Mint value into the shielded pool.
		///
		/// Deducts `value` from the sender's public balance and stores the
		/// Pedersen commitment on-chain. The `commitment_point` must be the
		/// compressed serialization of a valid Pallas affine point.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(100_000_000, 0))]
		pub fn mint(
			origin: OriginFor<T>,
			#[pallet::compact] value: u128,
			commitment_point: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Validate and compute canonical storage key
			let commitment_key = commitment::point_key_from_bytes(&commitment_point)
				.ok_or(Error::<T>::InvalidCommitment)?;

			// Ensure commitment doesn't already exist
			ensure!(
				!NoteCommitments::<T>::contains_key(&commitment_key),
				Error::<T>::CommitmentAlreadyExists
			);

			// Deduct from public balance
			let amount =
				<T as pallet_balances::Config>::Balance::try_from(value)
					.map_err(|_| Error::<T>::InsufficientBalance)?;
			let _ = <pallet_balances::Pallet<T> as frame_support::traits::Currency<T::AccountId>>::withdraw(
				&who,
				amount,
				frame_support::traits::WithdrawReasons::TRANSFER,
				frame_support::traits::ExistenceRequirement::KeepAlive,
			)
			.map_err(|_| Error::<T>::InsufficientBalance)?;

			// Store commitment and update pool balance
			NoteCommitments::<T>::insert(&commitment_key, ());
			PoolBalance::<T>::mutate(|bal| *bal = bal.saturating_add(value));

			Self::deposit_event(Event::NoteMinted { who, commitment: commitment_key, value });
			Ok(())
		}

		/// Burn a shielded note back to a public balance.
		///
		/// The sender reveals the value and blinding factor to prove ownership.
		/// The commitment is recomputed as `value * G + blinding * H` and its
		/// storage key is verified to exist on-chain.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(100_000_000, 0))]
		pub fn burn(
			origin: OriginFor<T>,
			#[pallet::compact] value: u128,
			blinding: Vec<u8>,
			nullifier: [u8; 32],
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Verify nullifier hasn't been spent
			ensure!(
				!Nullifiers::<T>::contains_key(&nullifier),
				Error::<T>::NullifierAlreadySpent
			);

			// Recompute commitment from revealed value and blinding
			let blinding_scalar = commitment::decode_scalar(&blinding)
				.ok_or(Error::<T>::InvalidCommitment)?;
			let expected_point = commitment::commit(value, &blinding_scalar);
			let commitment_key = commitment::point_to_key(&expected_point);

			// Verify commitment exists
			ensure!(
				NoteCommitments::<T>::contains_key(&commitment_key),
				Error::<T>::CommitmentNotFound
			);

			// Mark nullifier as spent, remove commitment
			Nullifiers::<T>::insert(&nullifier, ());
			NoteCommitments::<T>::remove(&commitment_key);
			PoolBalance::<T>::mutate(|bal| *bal = bal.saturating_sub(value));

			// Credit public balance
			let amount =
				<T as pallet_balances::Config>::Balance::try_from(value)
					.map_err(|_| Error::<T>::InsufficientBalance)?;
			let _ = <pallet_balances::Pallet<T> as frame_support::traits::Currency<T::AccountId>>::deposit_creating(
				&who,
				amount,
			);

			Self::deposit_event(Event::NoteBurned { who, nullifier, value });
			Ok(())
		}

		/// Transfer shielded notes.
		///
		/// Spends existing notes (by publishing nullifiers) and creates new
		/// shielded notes. Balance conservation is verified homomorphically:
		///   sum(C_in) - sum(C_out) == balance_blinding * H
		///
		/// Commitment points are provided as compressed serialized Pallas affine
		/// points. The pallet looks up input commitments by their blake2_256 key.
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::from_parts(200_000_000, 0))]
		pub fn transfer(
			origin: OriginFor<T>,
			input_nullifiers: Vec<[u8; 32]>,
			input_commitment_points: Vec<Vec<u8>>,
			output_commitment_points: Vec<Vec<u8>>,
			balance_blinding: Vec<u8>,
		) -> DispatchResult {
			ensure_signed(origin)?;

			// Input counts must match
			ensure!(
				input_nullifiers.len() == input_commitment_points.len(),
				Error::<T>::BalanceMismatch
			);

			// Verify all nullifiers are fresh
			for nullifier in &input_nullifiers {
				ensure!(
					!Nullifiers::<T>::contains_key(nullifier),
					Error::<T>::NullifierAlreadySpent
				);
			}

			// Validate input commitment points and verify they exist on-chain
			let mut input_keys = Vec::new();
			for point_bytes in &input_commitment_points {
				let key = commitment::point_key_from_bytes(point_bytes)
					.ok_or(Error::<T>::InvalidCommitment)?;
				ensure!(
					NoteCommitments::<T>::contains_key(&key),
					Error::<T>::CommitmentNotFound
				);
				input_keys.push(key);
			}

			// Validate output commitment points and ensure they don't already exist
			let mut output_keys = Vec::new();
			for point_bytes in &output_commitment_points {
				let key = commitment::point_key_from_bytes(point_bytes)
					.ok_or(Error::<T>::InvalidCommitment)?;
				ensure!(
					!NoteCommitments::<T>::contains_key(&key),
					Error::<T>::CommitmentAlreadyExists
				);
				output_keys.push(key);
			}

			// Verify balance: sum(inputs) - sum(outputs) == balance_blinding * H
			ensure!(
				commitment::verify_balance(
					&input_commitment_points,
					&output_commitment_points,
					&balance_blinding,
				),
				Error::<T>::BalanceMismatch
			);

			// Mark nullifiers as spent
			for nullifier in &input_nullifiers {
				Nullifiers::<T>::insert(nullifier, ());
			}
			// Remove input commitments
			for key in &input_keys {
				NoteCommitments::<T>::remove(key);
			}
			// Store output commitments
			for key in &output_keys {
				NoteCommitments::<T>::insert(key, ());
			}

			Self::deposit_event(Event::NoteTransferred {
				nullifiers: input_nullifiers,
				new_commitments: output_keys,
			});
			Ok(())
		}
	}
}
