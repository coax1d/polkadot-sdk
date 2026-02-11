use crate::{commitment, mock::*, Error, Event};
use ark_std::{test_rng, UniformRand};
use frame_support::{assert_noop, assert_ok};
use sp_crypto_ec_utils::pallas::ScalarField;

#[test]
fn mint_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mut rng = test_rng();
		let value = 500u128;
		let blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(value, &blinding);
		let point_bytes = commitment::serialize_point(&point);
		let expected_key = commitment::point_to_key(&point);

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), value, point_bytes));

		// Check commitment stored
		assert!(crate::NoteCommitments::<Test>::contains_key(&expected_key));
		// Check pool balance updated
		assert_eq!(crate::PoolBalance::<Test>::get(), 500);
		// Check public balance decreased
		assert_eq!(Balances::free_balance(1), 10_000 - 500);
		// Check event
		System::assert_last_event(
			Event::NoteMinted { who: 1, commitment: expected_key, value: 500 }.into(),
		);
	});
}

#[test]
fn mint_invalid_point_fails() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ShieldedPool::mint(RuntimeOrigin::signed(1), 100, vec![0xff; 33]),
			Error::<Test>::InvalidCommitment
		);
	});
}

#[test]
fn mint_duplicate_commitment_fails() {
	new_test_ext().execute_with(|| {
		let mut rng = test_rng();
		let blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(100, &blinding);
		let bytes = commitment::serialize_point(&point);

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 100, bytes.clone()));
		assert_noop!(
			ShieldedPool::mint(RuntimeOrigin::signed(1), 100, bytes),
			Error::<Test>::CommitmentAlreadyExists
		);
	});
}

#[test]
fn mint_insufficient_balance_fails() {
	new_test_ext().execute_with(|| {
		let mut rng = test_rng();
		let blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(20_000, &blinding);
		let bytes = commitment::serialize_point(&point);

		assert_noop!(
			ShieldedPool::mint(RuntimeOrigin::signed(1), 20_000, bytes),
			Error::<Test>::InsufficientBalance
		);
	});
}

#[test]
fn burn_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mut rng = test_rng();
		let value = 500u128;
		let blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(value, &blinding);
		let point_bytes = commitment::serialize_point(&point);
		let commitment_key = commitment::point_to_key(&point);
		let blinding_bytes = commitment::encode_scalar(&blinding);
		let nullifier = sp_core::hashing::blake2_256(b"test-nullifier");

		// First mint
		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), value, point_bytes));
		assert_eq!(Balances::free_balance(1), 10_000 - 500);

		// Then burn
		assert_ok!(ShieldedPool::burn(
			RuntimeOrigin::signed(1),
			value,
			blinding_bytes,
			nullifier,
		));

		// Check commitment removed
		assert!(!crate::NoteCommitments::<Test>::contains_key(&commitment_key));
		// Check nullifier recorded
		assert!(crate::Nullifiers::<Test>::contains_key(&nullifier));
		// Check pool balance
		assert_eq!(crate::PoolBalance::<Test>::get(), 0);
		// Check public balance restored
		assert_eq!(Balances::free_balance(1), 10_000);
		// Check event
		System::assert_last_event(
			Event::NoteBurned { who: 1, nullifier, value: 500 }.into(),
		);
	});
}

#[test]
fn burn_double_spend_fails() {
	new_test_ext().execute_with(|| {
		let mut rng = test_rng();
		let blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(500, &blinding);
		let point_bytes = commitment::serialize_point(&point);
		let blinding_bytes = commitment::encode_scalar(&blinding);
		let nullifier = sp_core::hashing::blake2_256(b"test-nullifier");

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 500, point_bytes));
		assert_ok!(ShieldedPool::burn(
			RuntimeOrigin::signed(1),
			500,
			blinding_bytes.clone(),
			nullifier,
		));

		// Second burn with same nullifier fails
		assert_noop!(
			ShieldedPool::burn(RuntimeOrigin::signed(1), 500, blinding_bytes, nullifier),
			Error::<Test>::NullifierAlreadySpent
		);
	});
}

#[test]
fn burn_wrong_blinding_fails() {
	new_test_ext().execute_with(|| {
		let mut rng = test_rng();
		let blinding = ScalarField::rand(&mut rng);
		let wrong_blinding = ScalarField::rand(&mut rng);
		let point = commitment::commit(500, &blinding);
		let point_bytes = commitment::serialize_point(&point);
		let wrong_bytes = commitment::encode_scalar(&wrong_blinding);
		let nullifier = sp_core::hashing::blake2_256(b"test-nullifier");

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 500, point_bytes));

		// Wrong blinding produces a different commitment key that won't be found
		assert_noop!(
			ShieldedPool::burn(RuntimeOrigin::signed(1), 500, wrong_bytes, nullifier),
			Error::<Test>::CommitmentNotFound
		);
	});
}

#[test]
fn transfer_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mut rng = test_rng();

		// Mint two input notes: 500 and 300
		let r1 = ScalarField::rand(&mut rng);
		let r2 = ScalarField::rand(&mut rng);
		let c_in_1 = commitment::commit(500, &r1);
		let c_in_2 = commitment::commit(300, &r2);
		let bytes_in_1 = commitment::serialize_point(&c_in_1);
		let bytes_in_2 = commitment::serialize_point(&c_in_2);

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 500, bytes_in_1.clone()));
		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 300, bytes_in_2.clone()));

		// Create two output notes: 600 and 200 (same total: 800)
		let r3 = ScalarField::rand(&mut rng);
		let r4 = ScalarField::rand(&mut rng);
		let c_out_1 = commitment::commit(600, &r3);
		let c_out_2 = commitment::commit(200, &r4);
		let bytes_out_1 = commitment::serialize_point(&c_out_1);
		let bytes_out_2 = commitment::serialize_point(&c_out_2);

		// balance_blinding = sum(r_in) - sum(r_out)
		let balance_blinding = (r1 + r2) - (r3 + r4);
		let bb_bytes = commitment::encode_scalar(&balance_blinding);

		let nullifier1 = sp_core::hashing::blake2_256(b"nullifier-1");
		let nullifier2 = sp_core::hashing::blake2_256(b"nullifier-2");

		assert_ok!(ShieldedPool::transfer(
			RuntimeOrigin::signed(1),
			vec![nullifier1, nullifier2],
			vec![bytes_in_1, bytes_in_2],
			vec![bytes_out_1, bytes_out_2],
			bb_bytes,
		));

		// Check nullifiers are spent
		assert!(crate::Nullifiers::<Test>::contains_key(&nullifier1));
		assert!(crate::Nullifiers::<Test>::contains_key(&nullifier2));
		// Check old commitments removed, new ones added
		let key_in_1 = commitment::point_to_key(&c_in_1);
		let key_in_2 = commitment::point_to_key(&c_in_2);
		let key_out_1 = commitment::point_to_key(&c_out_1);
		let key_out_2 = commitment::point_to_key(&c_out_2);
		assert!(!crate::NoteCommitments::<Test>::contains_key(&key_in_1));
		assert!(!crate::NoteCommitments::<Test>::contains_key(&key_in_2));
		assert!(crate::NoteCommitments::<Test>::contains_key(&key_out_1));
		assert!(crate::NoteCommitments::<Test>::contains_key(&key_out_2));
		// Pool balance unchanged (800 in, 800 out shielded)
		assert_eq!(crate::PoolBalance::<Test>::get(), 800);
	});
}

#[test]
fn unbalanced_transfer_fails() {
	new_test_ext().execute_with(|| {
		let mut rng = test_rng();

		let r1 = ScalarField::rand(&mut rng);
		let c_in = commitment::commit(500, &r1);
		let bytes_in = commitment::serialize_point(&c_in);

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 500, bytes_in.clone()));

		// Output has different value (600 != 500)
		let r2 = ScalarField::rand(&mut rng);
		let c_out = commitment::commit(600, &r2);
		let bytes_out = commitment::serialize_point(&c_out);

		// balance_blinding as if values balance (they don't)
		let bb = r1 - r2;
		let bb_bytes = commitment::encode_scalar(&bb);

		let nullifier = sp_core::hashing::blake2_256(b"nullifier");

		assert_noop!(
			ShieldedPool::transfer(
				RuntimeOrigin::signed(1),
				vec![nullifier],
				vec![bytes_in],
				vec![bytes_out],
				bb_bytes,
			),
			Error::<Test>::BalanceMismatch
		);
	});
}

#[test]
fn full_lifecycle_mint_transfer_burn() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mut rng = test_rng();

		// Step 1: Alice mints 1000 into shielded pool
		let r1 = ScalarField::rand(&mut rng);
		let c1 = commitment::commit(1000, &r1);
		let c1_bytes = commitment::serialize_point(&c1);

		assert_ok!(ShieldedPool::mint(RuntimeOrigin::signed(1), 1000, c1_bytes.clone()));
		assert_eq!(Balances::free_balance(1), 9_000);

		// Step 2: Transfer 1000 → 700 + 300
		let r2 = ScalarField::rand(&mut rng);
		let r3 = ScalarField::rand(&mut rng);
		let c_out_700 = commitment::commit(700, &r2);
		let c_out_300 = commitment::commit(300, &r3);
		let bytes_700 = commitment::serialize_point(&c_out_700);
		let bytes_300 = commitment::serialize_point(&c_out_300);

		let bb = r1 - (r2 + r3);
		let bb_bytes = commitment::encode_scalar(&bb);

		let null1 = sp_core::hashing::blake2_256(b"null-1");

		assert_ok!(ShieldedPool::transfer(
			RuntimeOrigin::signed(1),
			vec![null1],
			vec![c1_bytes],
			vec![bytes_700.clone(), bytes_300],
			bb_bytes,
		));

		// Step 3: Burn the 700 note back to public balance (user 2)
		let blinding_bytes_2 = commitment::encode_scalar(&r2);
		let null2 = sp_core::hashing::blake2_256(b"null-2");

		assert_ok!(ShieldedPool::burn(RuntimeOrigin::signed(2), 700, blinding_bytes_2, null2));
		assert_eq!(Balances::free_balance(2), 10_700);
		assert_eq!(crate::PoolBalance::<Test>::get(), 300);
	});
}
