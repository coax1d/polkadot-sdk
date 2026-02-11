//! Pedersen commitment helpers using the Pallas elliptic curve.
//!
//! A Pedersen commitment to value `v` with blinding factor `r` is:
//!   C = v * G + r * H
//!
//! where G is the Pallas generator and H is a second independent generator
//! derived deterministically.
//!
//! Commitments are stored on-chain as 33-byte compressed affine point
//! serializations (padded to 64 bytes for storage alignment), identified by
//! their blake2_256 hash as the storage key.

extern crate alloc;

use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use sp_crypto_ec_utils::pallas::{Affine, Projective, ScalarField};

/// Derive the second generator H by multiplying G by a fixed scalar derived
/// from a domain-separated hash. A production system would use a proper
/// hash-to-curve construction; this is sufficient for a PoC.
fn generator_h() -> Affine {
	let hash = sp_core::hashing::blake2_256(b"zcash-poc-shielded-pool-generator-H");
	let mut wide = [0u8; 64];
	wide[..32].copy_from_slice(&hash);
	let scalar = ScalarField::from_le_bytes_mod_order(&wide[..]);
	(Affine::generator() * scalar).into_affine()
}

/// Create a Pedersen commitment: C = value * G + blinding * H
pub fn commit(value: u128, blinding: &ScalarField) -> Affine {
	let g = Affine::generator();
	let h = generator_h();
	let v_scalar = ScalarField::from(value);
	<Projective as VariableBaseMSM>::msm(&[g, h], &[v_scalar, *blinding])
		.expect("MSM with 2 bases and 2 scalars cannot fail; qed")
		.into_affine()
}

/// Serialize an affine point to compressed bytes.
pub fn serialize_point(point: &Affine) -> Vec<u8> {
	let mut buf = Vec::new();
	point
		.serialize_with_mode(&mut buf, Compress::Yes)
		.expect("Affine point serialization cannot fail; qed");
	buf
}

/// Deserialize a compressed affine point, validating it lies on the curve.
pub fn deserialize_point(bytes: &[u8]) -> Option<Affine> {
	Affine::deserialize_with_mode(&mut &bytes[..], Compress::Yes, Validate::Yes).ok()
}

/// Compute the 32-byte storage key for a commitment point.
pub fn point_to_key(point: &Affine) -> [u8; 32] {
	sp_core::hashing::blake2_256(&serialize_point(point))
}

/// Validate that bytes represent a valid compressed Pallas curve point.
pub fn is_valid_point(bytes: &[u8]) -> bool {
	deserialize_point(bytes).is_some()
}

/// Compute the storage key from raw serialized point bytes.
///
/// Deserializes to validate, then re-serializes to get canonical bytes
/// before hashing. Returns `None` if the bytes are not a valid point.
pub fn point_key_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
	let point = deserialize_point(bytes)?;
	Some(point_to_key(&point))
}

/// Verify that a commitment key matches the given value and blinding factor.
/// Recomputes C = value * G + blinding * H and checks the storage key matches.
pub fn verify_commitment(commitment_key: &[u8; 32], value: u128, blinding_bytes: &[u8]) -> bool {
	let blinding = match decode_scalar(blinding_bytes) {
		Some(s) => s,
		None => return false,
	};

	let expected = commit(value, &blinding);
	let expected_key = point_to_key(&expected);
	*commitment_key == expected_key
}

/// Verify balance conservation for a shielded transfer.
///
/// Given serialized input commitment points (being spent) and output commitment
/// points (being created), verify that:
///
///   sum(C_in) - sum(C_out) == balance_blinding * H
///
/// If values balance (sum(v_in) == sum(v_out)), the excess commitment only has
/// an H component from the blinding factor difference. The caller provides
/// `balance_blinding = sum(r_in) - sum(r_out)` to prove consistency.
pub fn verify_balance(
	input_points: &[Vec<u8>],
	output_points: &[Vec<u8>],
	balance_blinding_bytes: &[u8],
) -> bool {
	let balance_blinding = match decode_scalar(balance_blinding_bytes) {
		Some(s) => s,
		None => return false,
	};

	// Deserialize all input commitment points
	let mut sum_in = Projective::default();
	for p_bytes in input_points {
		let point = match deserialize_point(p_bytes) {
			Some(p) => p,
			None => return false,
		};
		sum_in = sum_in + point;
	}

	// Deserialize all output commitment points
	let mut sum_out = Projective::default();
	for p_bytes in output_points {
		let point = match deserialize_point(p_bytes) {
			Some(p) => p,
			None => return false,
		};
		sum_out = sum_out + point;
	}

	// Excess = sum(inputs) - sum(outputs)
	let excess = (sum_in - sum_out).into_affine();

	// Expected excess = balance_blinding * H
	let h = generator_h();
	let expected_excess = (h * balance_blinding).into_affine();

	excess == expected_excess
}

/// Decode a scalar field element from compressed serialization bytes.
pub fn decode_scalar(bytes: &[u8]) -> Option<ScalarField> {
	ScalarField::deserialize_with_mode(&mut &bytes[..], Compress::Yes, Validate::Yes).ok()
}

/// Encode a scalar field element to compressed serialization bytes.
pub fn encode_scalar(scalar: &ScalarField) -> Vec<u8> {
	let mut buf = Vec::new();
	scalar
		.serialize_with_mode(&mut buf, Compress::Yes)
		.expect("Scalar serialization cannot fail; qed");
	buf
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_std::{test_rng, UniformRand};

	#[test]
	fn commit_and_verify_works() {
		let mut rng = test_rng();
		let value = 1000u128;
		let blinding = ScalarField::rand(&mut rng);

		let c = commit(value, &blinding);
		let c_key = point_to_key(&c);

		let blinding_bytes = encode_scalar(&blinding);
		assert!(verify_commitment(&c_key, value, &blinding_bytes));
	}

	#[test]
	fn wrong_value_fails_verification() {
		let mut rng = test_rng();
		let value = 1000u128;
		let blinding = ScalarField::rand(&mut rng);

		let c = commit(value, &blinding);
		let c_key = point_to_key(&c);

		let blinding_bytes = encode_scalar(&blinding);
		assert!(!verify_commitment(&c_key, 999u128, &blinding_bytes));
	}

	#[test]
	fn wrong_blinding_fails_verification() {
		let mut rng = test_rng();
		let value = 1000u128;
		let blinding = ScalarField::rand(&mut rng);
		let wrong_blinding = ScalarField::rand(&mut rng);

		let c = commit(value, &blinding);
		let c_key = point_to_key(&c);

		let wrong_bytes = encode_scalar(&wrong_blinding);
		assert!(!verify_commitment(&c_key, value, &wrong_bytes));
	}

	#[test]
	fn homomorphic_property_holds() {
		let mut rng = test_rng();
		let v1 = 500u128;
		let v2 = 300u128;
		let r1 = ScalarField::rand(&mut rng);
		let r2 = ScalarField::rand(&mut rng);

		let c1 = commit(v1, &r1);
		let c2 = commit(v2, &r2);
		let c_sum = (c1 + c2).into_affine();

		let r_sum = r1 + r2;
		let c_direct = commit(v1 + v2, &r_sum);

		assert_eq!(c_sum, c_direct);
	}

	#[test]
	fn balance_verification_works() {
		let mut rng = test_rng();

		// Create two input notes: 500 and 300
		let r1 = ScalarField::rand(&mut rng);
		let r2 = ScalarField::rand(&mut rng);
		let c_in_1 = commit(500, &r1);
		let c_in_2 = commit(300, &r2);

		// Create two output notes: 600 and 200 (same total: 800)
		let r3 = ScalarField::rand(&mut rng);
		let r4 = ScalarField::rand(&mut rng);
		let c_out_1 = commit(600, &r3);
		let c_out_2 = commit(200, &r4);

		// balance_blinding = sum(r_in) - sum(r_out)
		let balance_blinding = (r1 + r2) - (r3 + r4);

		let inputs = vec![serialize_point(&c_in_1), serialize_point(&c_in_2)];
		let outputs = vec![serialize_point(&c_out_1), serialize_point(&c_out_2)];
		let bb_bytes = encode_scalar(&balance_blinding);

		assert!(verify_balance(&inputs, &outputs, &bb_bytes));
	}

	#[test]
	fn unbalanced_transfer_fails() {
		let mut rng = test_rng();

		let r1 = ScalarField::rand(&mut rng);
		let c_in = commit(500, &r1);

		// Output has different value
		let r2 = ScalarField::rand(&mut rng);
		let c_out = commit(600, &r2);

		// balance_blinding computed as if values balance (they don't)
		let balance_blinding = r1 - r2;

		let inputs = vec![serialize_point(&c_in)];
		let outputs = vec![serialize_point(&c_out)];
		let bb_bytes = encode_scalar(&balance_blinding);

		assert!(!verify_balance(&inputs, &outputs, &bb_bytes));
	}

	#[test]
	fn point_serialization_roundtrip() {
		let mut rng = test_rng();
		let blinding = ScalarField::rand(&mut rng);
		let point = commit(42, &blinding);

		let bytes = serialize_point(&point);
		let recovered = deserialize_point(&bytes).expect("valid point");
		assert_eq!(point, recovered);
	}

	#[test]
	fn is_valid_point_rejects_garbage() {
		assert!(!is_valid_point(&[0xff; 33]));
		assert!(!is_valid_point(&[0u8; 10]));
	}
}
