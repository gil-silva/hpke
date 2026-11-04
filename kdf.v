// kdf.v carries the labeled HKDF layer of RFC 9180 (sections 4 and 5.1):
// the LabeledExtract/LabeledExpand constructions, the KEM-level helpers
// with their fixed HKDF-SHA256 binding, the context key schedule and the
// exporter interface.
module hpke

import gil_silva.chacha20poly1305
import crypto.hkdf
import crypto.sha256
import crypto.sha512

// hpke_version is the version prefix every HPKE label carries (RFC 9180,
// section 4).
const hpke_version = 'HPKE-v1'

// kctx collects the three secrets the key schedule derives for one context.
struct Kctx {
	key             []u8
	base_nonce      []u8
	exporter_secret []u8
}

// i2osp2 encodes a length as its fixed-width two-byte big-endian form (the
// I2OSP calls of RFC 9180).
fn i2osp2(l int) []u8 {
	return [u8(l >> 8), u8(l & 0xff)]
}

// suite_id returns the HPKE context suite identifier: the string "HPKE"
// followed by the two-byte KEM, KDF and AEAD identifiers (RFC 9180, section
// 7.1).
fn (s Suite) suite_id() []u8 {
	mut id := 'HPKE'.bytes()
	id << i2osp2(int(s.kem))
	id << i2osp2(int(s.kdf))
	id << i2osp2(int(s.aead))
	return id
}

// kem_suite_id returns the KEM-level suite identifier: the string "KEM"
// followed by the two-byte KEM identifier (RFC 9180, section 7.1). The KEM
// labels are independent of the context KDF choice.
fn kem_suite_id() []u8 {
	mut id := 'KEM'.bytes()
	id << i2osp2(int(kem_id_x25519))
	return id
}

// nh returns the hash output length of the context KDF in bytes.
fn (s Suite) nh() int {
	return if s.kdf == kdf_sha512 { sha512.size } else { sha256.size }
}

// labeled_extract_raw runs HKDF-Extract over the labeled IKM: the version
// string, the suite identifier, the label and the IKM, in order (RFC 9180,
// section 4). kdf selects the digest hash and suite_id_bytes the
// distinction between the context and the KEM suite identifier.
fn labeled_extract_raw(suite_id_bytes []u8, kdf u16, salt []u8, label string, ikm []u8) ![]u8 {
	mut labeled_ikm := hpke_version.bytes()
	labeled_ikm << suite_id_bytes
	labeled_ikm << label.bytes()
	labeled_ikm << ikm
	if kdf == kdf_sha512 {
		return hkdf.extract(sha512.new, labeled_ikm, salt)!
	}
	return hkdf.extract(sha256.new, labeled_ikm, salt)!
}

// labeled_expand_raw runs HKDF-Expand over the labeled prefix: the encoded
// output length, the version string, the suite identifier, the label and
// the info string, in order (RFC 9180, section 4).
fn labeled_expand_raw(suite_id_bytes []u8, kdf u16, prk []u8, label string, info []u8, l int) ![]u8 {
	mut labeled_info := i2osp2(l)
	labeled_info << hpke_version.bytes()
	labeled_info << suite_id_bytes
	labeled_info << label.bytes()
	labeled_info << info
	if kdf == kdf_sha512 {
		return hkdf.expand(sha512.new, prk, labeled_info.bytestr(), l)!
	}
	return hkdf.expand(sha256.new, prk, labeled_info.bytestr(), l)!
}

// labeled_extract runs the labeled HKDF-Extract with the context suite
// identifier and hashing (RFC 9180, section 4).
fn (s Suite) labeled_extract(salt []u8, label string, ikm []u8) ![]u8 {
	return labeled_extract_raw(s.suite_id(), s.kdf, salt, label, ikm)
}

// labeled_expand runs the labeled HKDF-Expand with the context suite
// identifier and hashing (RFC 9180, section 4).
fn (s Suite) labeled_expand(prk []u8, label string, info []u8, l int) ![]u8 {
	return labeled_expand_raw(s.suite_id(), s.kdf, prk, label, info, l)
}

// kem_extract runs the KEM-level labeled HKDF-Extract: DHKEM(X25519) is
// bound to HKDF-SHA256 and to the KEM suite identifier, independently of
// the context KDF (RFC 9180, section 4.1).
fn kem_extract(salt []u8, label string, ikm []u8) ![]u8 {
	return labeled_extract_raw(kem_suite_id(), kdf_sha256, salt, label, ikm)
}

// kem_expand runs the KEM-level labeled HKDF-Expand with the same fixed
// binding as kem_extract (RFC 9180, section 4.1).
fn kem_expand(prk []u8, label string, info []u8, l int) ![]u8 {
	return labeled_expand_raw(kem_suite_id(), kdf_sha256, prk, label, info, l)
}

// key_schedule derives the context secrets of RFC 9180 (section 5.1): the
// two parameter hashes over the empty salt folded into the key schedule
// context, one Extract over the shared secret and the PSK, and the three
// Expansions for the AEAD key, base nonce and exporter secret. The
// export-only AEAD computes no key and no base nonce.
fn (s Suite) key_schedule(mode u8, shared_secret []u8, info []u8, o SetupOpts) !Kctx {
	psk_id_hash := s.labeled_extract([], 'psk_id_hash', o.psk_id)!
	info_hash := s.labeled_extract([], 'info_hash', info)!
	mut ks_context := []u8{}
	ks_context << mode
	ks_context << psk_id_hash
	ks_context << info_hash
	secret := s.labeled_extract(shared_secret, 'secret', o.psk)!
	mut key := []u8{}
	mut base_nonce := []u8{}
	if s.aead == aead_chacha20poly1305 {
		key = s.labeled_expand(secret, 'key', ks_context, chacha20poly1305.key_size)!
		base_nonce = s.labeled_expand(secret, 'base_nonce', ks_context, chacha20poly1305.nonce_size)!
	}
	exporter_secret := s.labeled_expand(secret, 'exp', ks_context, s.nh())!
	return Kctx{
		key:             key
		base_nonce:      base_nonce
		exporter_secret: exporter_secret
	}
}

// export_secret derives an exporter value over the exporter secret (RFC
// 9180, section 5.3): the output length must be between 1 and 2^16 - 1
// bytes and within the HKDF-Expand limit of the suite KDF, 255 bytes times
// the hash size Nh.
fn export_secret(s Suite, exporter_secret []u8, context []u8, l int) ![]u8 {
	if l < 1 || l > 65535 {
		return verror('export size out of range: must be between 1 and 65535, got ${l}')
	}
	limit := 255 * s.nh()
	if l > limit {
		return verror('export size out of range: up to ${limit} bytes for this suite KDF, got ${l}')
	}
	return s.labeled_expand(exporter_secret, 'sec', context, l)!
}
