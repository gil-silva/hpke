// Tests for the hpke module, verified against the official RFC 9180 test
// vectors vendored in testkit/hpke_x25519.json (the vector set the RFC 9180
// appendix A was generated from, filtered to the X25519 KEM suites this
// module implements: the HKDF-SHA256/SHA512 x ChaCha20-Poly1305 and
// export-only AEAD combinations, all four protocol modes). For every vector
// the test checks the deterministic key derivation, the KEM encapsulation
// and its authenticated variant, every key schedule field, all ciphertext
// records with their nonce material and all exporter records, and runs a
// random full round trip plus the rejection behavior on top.
module hpke

import encoding.hex
import json2
import os

struct VecEnc {
	aad   string
	ct    string
	nonce string
	pt    string
}

struct VecExport {
	exporter_context string
	l                int @[json: 'L']
	exported_value   string
}

struct Vec {
	mode            int
	kem_id          int
	kdf_id          int
	aead_id         int
	psk             string
	psk_id          string
	info            string
	ikm_e           string @[json: 'ikmE']
	ikm_r           string @[json: 'ikmR']
	ikm_s           string @[json: 'ikmS']
	sk_em           string @[json: 'skEm']
	pk_em           string @[json: 'pkEm']
	sk_rm           string @[json: 'skRm']
	pk_rm           string @[json: 'pkRm']
	sk_sm           string @[json: 'skSm']
	pk_sm           string @[json: 'pkSm']
	enc             string
	shared_secret   string
	key             string
	base_nonce      string
	exporter_secret string
	encryptions     []VecEnc
	exports         []VecExport
}

// import_vectors reads the vendored official vector file next to this test.
fn import_vectors() ![]Vec {
	src := @FILE
	vpath := os.join_path(src.all_before_last('/'), 'testkit', 'hpke_x25519.json')
	content := os.read_file(vpath) or {
		return error('cannot read the official vectors: ${err.msg()} (${vpath})')
	}
	return json2.decode[[]Vec](content, json2.DecoderOptions{})!
}

// hx decodes one hex field of the official vectors; the empty fields of the
// base modes and the export-only AEAD decode as empty byte slices.
fn hx(s string) []u8 {
	if s == '' {
		return []u8{}
	}
	return hex.decode(s) or { panic('bad hex vector field: ${err}') }
}

// rejects_seal reports whether a one-shot seal fails, for the usage and
// validation probes below.
fn rejects_seal(suite Suite, mode u8, pk_r []u8, o SetupOpts) bool {
	suite.seal(mode, pk_r, []u8{}, 'm'.bytes(), []u8{}, o) or { return true }
	return false
}

// rejects_open reports whether a one-shot open fails, for the usage and
// validation probes below.
fn rejects_open(suite Suite, mode u8, enc []u8, sk_r []u8, o SetupOpts) bool {
	suite.open(mode, enc, sk_r, []u8{}, []u8{}, []u8{}, o) or { return true }
	return false
}

// suite_rejects reports whether new_suite rejects the given identifiers.
fn suite_rejects(kdf u16, aead u16) bool {
	new_suite(kdf, aead) or { return true }
	return false
}

// run_vector checks all parts of one official vector.
fn run_vector(v Vec) ! {
	suite := new_suite(u16(v.kdf_id), u16(v.aead_id))!
	mode := u8(v.mode)
	auth := mode == mode_auth || mode == mode_auth_psk
	info := hx(v.info)

	// 1. The deterministic key derivation of the KEM produces the
	// serialized key material the vector records, for the ephemeral and
	// the recipient keys and, in the authenticated modes, the sender key.
	sk_e, pk_e := derive_key_pair(hx(v.ikm_e))!
	assert sk_e == hx(v.sk_em)
	assert pk_e == hx(v.pk_em)
	sk_r, pk_r := derive_key_pair(hx(v.ikm_r))!
	assert sk_r == hx(v.sk_rm)
	assert pk_r == hx(v.pk_rm)
	opts := SetupOpts{
		psk:    hx(v.psk)
		psk_id: hx(v.psk_id)
	}
	mut sk_s := []u8{}
	mut pk_s := []u8{}
	if auth {
		sk_s, pk_s = derive_key_pair(hx(v.ikm_s))!
		assert sk_s == hx(v.sk_sm)
		assert pk_s == hx(v.pk_sm)
	}

	// 2. The KEM encapsulation recovers the encapsulated key and the
	// shared secret of the vector; the receiver side rederives both.
	mut enc := []u8{}
	mut shared := []u8{}
	if auth {
		enc, shared = suite.auth_encap(pk_r, sk_e, pk_e, sk_s)!
	} else {
		enc, shared = suite.encap(pk_r, sk_e, pk_e)!
	}
	assert enc == hx(v.enc)
	assert shared == hx(v.shared_secret)
	mut recovered := []u8{}
	if auth {
		recovered = suite.auth_decap(enc, sk_r, pk_s)!
	} else {
		recovered = suite.decap(enc, sk_r)!
	}
	assert recovered == shared, 'receiver reruns the KEM and rederives the shared secret'

	// 3. The key schedule reproduces the recorded key, base nonce and
	// exporter secret of the vector.
	sched := suite.key_schedule(mode, shared, info, opts)!
	assert sched.key == hx(v.key)
	assert sched.base_nonce == hx(v.base_nonce)
	assert sched.exporter_secret == hx(v.exporter_secret)

	// 4. Every recorded ciphertext seals and opens with the same nonce
	// material and the same sequence numbers.
	mut sender := Sender{
		suite:           suite
		key:             sched.key
		base_nonce:      sched.base_nonce
		exporter_secret: sched.exporter_secret
	}
	mut receiver := Receiver{
		suite:           suite
		key:             sched.key
		base_nonce:      sched.base_nonce
		exporter_secret: sched.exporter_secret
	}
	for e in v.encryptions {
		assert compute_nonce(sched.base_nonce, sender.seq) == hx(e.nonce)
		sealed := sender.seal(hx(e.pt), hx(e.aad))!
		assert sealed == hx(e.ct)
		pt := receiver.open(hx(e.ct), hx(e.aad))!
		assert pt == hx(e.pt)
	}
	if v.encryptions.len > 0 {
		assert sender.seq == u64(v.encryptions.len)
	}

	// 5. The exporter interface agrees between both sides and with the
	// recorded exports of the vector.
	for e in v.exports {
		expected := hx(e.exported_value)
		assert sender.export(hx(e.exporter_context), e.l)! == expected
		assert receiver.export(hx(e.exporter_context), e.l)! == expected
	}
}

fn test_official_vectors() {
	vectors := import_vectors() or { panic('${err}') }
	assert vectors.len == 16
	for i, v in vectors {
		run_vector(v) or {
			panic('official vector ${i} (mode ${v.mode}, kdf ${v.kdf_id}, aead ${v.aead_id}) failed: ${err.msg()}')
		}
	}
}

// test_random_roundtrips exercises the public API with fresh random keys:
// the context setup on both sides, a two-message sequence, the one-shot
// convenience calls and the exporter agreement over both KDFs.
fn test_random_roundtrips() {
	suite := new_suite(kdf_sha256, aead_chacha20poly1305)!
	sk_r, pk_r := generate_key_pair()!
	info := 'application context'.bytes()

	mut enc := []u8{}
	mut sender := Sender{}
	enc, sender = suite.setup_sender(mode_base, pk_r, info, SetupOpts{})!
	mut receiver := suite.setup_receiver(mode_base, enc, sk_r, info, SetupOpts{})!

	pt := 'first message'.bytes()
	ct := sender.seal(pt, 'aad'.bytes())!
	assert receiver.open(ct, 'aad'.bytes())! == pt
	ct2 := sender.seal('second message'.bytes(), []u8{})!
	assert receiver.open(ct2, []u8{})! == 'second message'.bytes()
	assert sender.seq == 2
	assert receiver.seq == 2
	assert sender.export('ctx'.bytes(), 64)! == receiver.export('ctx'.bytes(), 64)!

	// The one-shot form agrees with the context form.
	enc2, ct3 := suite.seal(mode_base, pk_r, info, 'hello hpke'.bytes(), 'aad'.bytes(), SetupOpts{})!
	assert suite.open(mode_base, enc2, sk_r, info, ct3, 'aad'.bytes(), SetupOpts{})! == 'hello hpke'.bytes()

	// The SHA-512 KDF drives its own schedule to the same plaintext.
	suite2 := new_suite(kdf_sha512, aead_chacha20poly1305)!
	enc3, ct4 := suite2.seal(mode_base, pk_r, info, 'hello again'.bytes(), 'aad'.bytes(), SetupOpts{})!
	assert suite2.open(mode_base, enc3, sk_r, info, ct4, 'aad'.bytes(), SetupOpts{})! == 'hello again'.bytes()
}

// test_usage_and_validation probes the rejection behavior: suite and mode
// identifiers, PSK and sender key combinations, key length framing and the
// export size range.
fn test_usage_and_validation() {
	// Unknown KDF and AEAD identifiers are unsupported; in particular the
	// AES-GCM suites, which pure V cannot provide.
	assert suite_rejects(kdf_sha512, u16(0x0001))
	assert suite_rejects(u16(0x0005), aead_chacha20poly1305)

	suite := new_suite(kdf_sha256, aead_chacha20poly1305)!
	sk_r, pk_r := generate_key_pair()!
	probe_enc, probe_ct := suite.seal(mode_base, pk_r, []u8{}, 'm'.bytes(), []u8{}, SetupOpts{})!
	assert suite.open(mode_base, probe_enc, sk_r, []u8{}, probe_ct, []u8{}, SetupOpts{})! == 'm'.bytes()

	// Unknown mode identifiers are unsupported on the sender and the
	// receiver side alike.
	assert rejects_seal(suite, u8(0x04), pk_r, SetupOpts{})
	mut unknown_mode := false
	unknown_open := suite.open(u8(0x04), probe_enc, sk_r, []u8{}, []u8{}, []u8{}, SetupOpts{}) or {
		unknown_mode = err is UnsupportedError
		[]u8{}
	}
	_ = unknown_open
	assert unknown_mode

	// The PSK modes require both PSK parts and nothing else.
	assert rejects_seal(suite, mode_base, pk_r, SetupOpts{
		psk:    'k'.bytes()
		psk_id: 'i'.bytes()
	})
	assert rejects_seal(suite, mode_psk, pk_r, SetupOpts{})
	assert rejects_seal(suite, mode_psk, pk_r, SetupOpts{
		psk: 'k'.bytes()
	})
	assert rejects_seal(suite, mode_psk, pk_r, SetupOpts{
		psk:    'k'.bytes()
		psk_id: 'i'.bytes()
		sk_s:   sk_r
	})
	assert rejects_seal(suite, mode_auth, pk_r, SetupOpts{})
	assert rejects_seal(suite, mode_auth_psk, pk_r, SetupOpts{
		sk_s: sk_r
	})

	// No mode accepts material it does not use; the sender static key
	// parts are reserved for their own side.
	assert rejects_seal(suite, mode_auth, pk_r, SetupOpts{
		pk_s: pk_r
	})
	assert rejects_open(suite, mode_psk, probe_enc, sk_r, SetupOpts{
		sk_s: sk_r
	})
	assert rejects_open(suite, mode_base, probe_enc, sk_r, SetupOpts{
		pk_s: pk_r
	})

	// Key material is framed at exactly 32 bytes, on both sides.
	assert rejects_seal(suite, mode_base, []u8{len: 31}, SetupOpts{})
	mut framing_rejected := false
	framed_open := suite.open(mode_base, []u8{len: 31}, sk_r, []u8{}, []u8{}, []u8{}, SetupOpts{}) or {
		framing_rejected = err is ValidationError
		[]u8{}
	}
	_ = framed_open
	assert framing_rejected

	// A sender context exposes the exporter interface.
	mut export_enc := []u8{}
	mut sender := Sender{}
	export_enc, sender = suite.setup_sender(mode_base, pk_r, []u8{}, SetupOpts{})!
	assert export_enc.len == 32

	// The export size range opens at 1 and closes at 65535.
	mut zero_rejected := false
	zero_export := sender.export([]u8{}, 0) or {
		zero_rejected = err is ValidationError
		[]u8{}
	}
	_ = zero_export
	assert zero_rejected
	mut huge_rejected := false
	huge_export := sender.export([]u8{}, 65536) or {
		huge_rejected = err is ValidationError
		[]u8{}
	}
	_ = huge_export
	assert huge_rejected
	mut negative_rejected := false
	negative_export := sender.export([]u8{}, -1) or {
		negative_rejected = err is ValidationError
		[]u8{}
	}
	_ = negative_export
	assert negative_rejected

	// The successful range runs from 1 byte up to the SHA-256 limit of
	// the underlying HKDF-Expand (255 * 32 bytes).
	export_1 := sender.export([]u8{}, 1)!
	assert export_1.len == 1
	export_32 := sender.export([]u8{}, 32)!
	assert export_32.len == 32
	export_max := sender.export([]u8{}, 255 * 32)!
	assert export_max.len == 255 * 32
}
