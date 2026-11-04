// kem.v implements the X25519 DH KEM of RFC 9180 (section 4.1): key
// generation and derivation, the encapsulation and decapsulation pair with
// its authenticated variants and the KEM ExtractAndExpand. The X25519
// arithmetic itself lives in gil_silva.x25519; this file composes it with
// the KEM labels and validates the serialized key material.
module hpke

import gil_silva.x25519
import crypto.rand

// generate_key_pair returns a fresh (sk, pk) X25519 pair, both in the raw
// 32-byte serialization. The secret key feeds scalar_mult and scalar_base
// directly: X25519 clamping is part of their arithmetic.
pub fn generate_key_pair() !([]u8, []u8) {
	sk := rand.bytes(x25519.size)!
	pk := x25519.scalar_base(sk)!
	return sk, pk
}

// derive_key_pair returns the deterministic (sk, pk) pair of the KEM key
// derivation of RFC 9180 (section 7.1.3): a labeled Expand over the
// "dkp_prk" PRK produces the secret key, whose public half is the X25519
// scalar multiplication with the curve base point. The official vectors
// drive every key material through it.
pub fn derive_key_pair(ikm []u8) !([]u8, []u8) {
	dkp_prk := kem_extract([], 'dkp_prk', ikm)!
	sk := kem_expand(dkp_prk, 'sk', [], x25519.size)!
	pk := x25519.scalar_base(sk)!
	return sk, pk
}

// validate_public_key checks the wire framing of one serialized scalar or
// point: every key material in this module is exactly 32 bytes.
fn validate_public_key(key []u8) ! {
	if key.len != x25519.size {
		return verror('invalid X25519 key material: must be ${x25519.size} bytes, got ${key.len}')
	}
}

// kem_shared_secret is the KEM ExtractAndExpand over one DH output:
// LabeledExtract with the "eae_prk" label and the empty salt, then
// LabeledExpand with the "shared_secret" label over the concatenated
// kem_context (RFC 9180, section 4.1). The X25519 KEM binds to HKDF-SHA256,
// so its Nh is 32.
fn kem_shared_secret(dh []u8, kem_context []u8) ![]u8 {
	prk := kem_extract([], 'eae_prk', dh)!
	return kem_expand(prk, 'shared_secret', kem_context, 32)
}

// encap encapsulates the shared secret to the recipient public key pk_r
// with the ephemeral (sk_em, pk_em) pair: it multiplies sk_em with pk_r,
// concatenates enc and pk_r into the kem_context and returns the
// encapsulated key
// (the raw enc form of pk_em) next to the shared secret (RFC 9180, section
// 4.1).
pub fn (s Suite) encap(pk_r []u8, sk_em []u8, pk_em []u8) !([]u8, []u8) {
	validate_public_key(pk_r)!
	validate_public_key(pk_em)!
	dh := x25519.scalar_mult(sk_em, pk_r)!
	mut kem_context := pk_em.clone()
	kem_context << pk_r
	shared := kem_shared_secret(dh, kem_context)!
	return pk_em.clone(), shared
}

// auth_encap is encap with sender authentication: the shared secret folds
// in the sender's own DH contribution, and the kem_context appends the
// sender public key derived from sk_s (RFC 9180, section 4.1).
pub fn (s Suite) auth_encap(pk_r []u8, sk_em []u8, pk_em []u8, sk_s []u8) !([]u8, []u8) {
	validate_public_key(pk_r)!
	validate_public_key(pk_em)!
	pk_s := x25519.scalar_base(sk_s)!
	dh1 := x25519.scalar_mult(sk_em, pk_r)!
	dh2 := x25519.scalar_mult(sk_s, pk_r)!
	mut dh := dh1.clone()
	dh << dh2
	mut kem_context := pk_em.clone()
	kem_context << pk_r
	kem_context << pk_s
	shared := kem_shared_secret(dh, kem_context)!
	return pk_em.clone(), shared
}

// decap recovers the shared secret of encap on the receiver side: the
// recipient private key multiplies the encapsulated key, and the result
// expands over the same kem_context of enc (RFC 9180, section 4.1). A low
// order encapsulated key fails inside the X25519 arithmetic.
pub fn (s Suite) decap(enc []u8, sk_r []u8) ![]u8 {
	validate_public_key(enc)!
	pk_r := x25519.scalar_base(sk_r)!
	dh := x25519.scalar_mult(sk_r, enc)!
	mut kem_context := enc.clone()
	kem_context << pk_r
	return kem_shared_secret(dh, kem_context)!
}

// auth_decap is decap with sender authentication: the receiver folds its
// own DH contribution with the sender public key into the shared secret
// and kem_context (RFC 9180, section 4.1).
pub fn (s Suite) auth_decap(enc []u8, sk_r []u8, pk_s []u8) ![]u8 {
	validate_public_key(enc)!
	validate_public_key(pk_s)!
	pk_r := x25519.scalar_base(sk_r)!
	dh1 := x25519.scalar_mult(sk_r, enc)!
	dh2 := x25519.scalar_mult(sk_r, pk_s)!
	mut dh := dh1.clone()
	dh << dh2
	mut kem_context := enc.clone()
	kem_context << pk_r
	kem_context << pk_s
	return kem_shared_secret(dh, kem_context)!
}
