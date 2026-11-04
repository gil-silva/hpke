// HPKE (RFC 9180) with the X25519 KEM, in pure V.
//
// The implementation composes gil_silva.x25519 (the X25519 DH KEM), the
// standard library HKDF (the context KDF) and gil_silva.chacha20poly1305
// (the ChaCha20-Poly1305 AEAD); the export-only AEAD mode implements the
// exporter interface of the specification. Every component is checked
// against the official RFC 9180 test vectors (see [Verification] in the
// README).
//
// No `unsafe` blocks; every fallible path returns a V result.
module hpke

import gil_silva.chacha20poly1305
import gil_silva.x25519
import crypto.rand

// Protocol mode identifiers (RFC 9180, section 7.1).
pub const mode_base = u8(0x00)
pub const mode_psk = u8(0x01)
pub const mode_auth = u8(0x02)
pub const mode_auth_psk = u8(0x03)

// kem_id_x25519 is the HPKE KEM identifier of DHKEM(X25519, HKDF-SHA256)
// (RFC 9180, section 7.1).
pub const kem_id_x25519 = u16(0x0020)

// kdf_sha256 and kdf_sha512 are the supported context KDF identifiers
// (HKDF-SHA256 and HKDF-SHA512, RFC 9180, section 7.1). The KEM itself is
// bound to HKDF-SHA256 by its definition.
pub const kdf_sha256 = u16(0x0001)
pub const kdf_sha512 = u16(0x0003)

// aead_chacha20poly1305 is the AEAD identifier of ChaCha20-Poly1305 (RFC
// 9180, section 7.1). The AES-GCM suites are not implemented in pure V; the
// export-only AEAD is available for key export alone.
pub const aead_chacha20poly1305 = u16(0x0003)

// aead_export_only is the AEAD identifier of the export-only mode (RFC 9180,
// section 7.1): the context computes no AEAD key and no base nonce, and
// only the exporter interface is available.
pub const aead_export_only = u16(0xffff)

// Suite is one HPKE cipher suite: the X25519 KEM is fixed, kdf selects the
// context KDF and aead the message protection.
pub struct Suite {
pub:
	kem  u16
	kdf  u16
	aead u16
}

// new_suite validates and returns the suite with the given KDF and AEAD
// identifiers over the X25519 KEM.
pub fn new_suite(kdf u16, aead u16) !Suite {
	if kdf != kdf_sha256 && kdf != kdf_sha512 {
		return unsupported('unsupported KDF identifier 0x${u32(kdf):x04}')
	}
	if aead != aead_chacha20poly1305 && aead != aead_export_only {
		return unsupported('unsupported AEAD identifier 0x${u32(aead):x04}')
	}
	return Suite{
		kem:  kem_id_x25519
		kdf:  kdf
		aead: aead
	}
}

// UnsupportedError marks a parameter combination the module does not
// implement: an unknown mode, KDF or AEAD identifier, or an operation the
// export-only AEAD cannot provide.
pub struct UnsupportedError {
	Error
	pool string
}

// msg returns the error text of UnsupportedError e.
pub fn (e UnsupportedError) msg() string {
	return e.pool
}

// ValidationError marks malformed protocol inputs: wrong public key
// lengths, incomplete or extraneous PSK and sender-key material, or
// out-of-range export sizes.
pub struct ValidationError {
	Error
	pool string
}

// msg returns the error text of ValidationError e.
pub fn (e ValidationError) msg() string {
	return e.pool
}

// unsupported builds an UnsupportedError with the given message.
fn unsupported(msg string) UnsupportedError {
	return UnsupportedError{
		pool: 'hpke: ${msg}'
	}
}

// verror builds a ValidationError with the given message.
fn verror(msg string) ValidationError {
	return ValidationError{
		pool: 'hpke: ${msg}'
	}
}

// SetupOpts carries the optional mode parameters: the PSK and its identifier
// for the PSK modes, and the sender's static X25519 key for the
// authenticated modes. pk_s is only read on the receiver side, where it
// authenticates the sender; on the sender side the public half is derived
// from sk_s.
pub struct SetupOpts {
pub:
	psk    []u8
	psk_id []u8
	sk_s   []u8
	pk_s   []u8
}

// Sender is the sender's encryption context: it encrypts each message under
// its own AEAD nonce and exposes the exporter interface. The per-key message
// limit R of RFC 9180 (2^(8*Nn) - 1 messages) exceeds the u64 sequence
// range, so the sequence arithmetic cannot reach it.
pub struct Sender {
pub mut:
	// seq is the sequence number of the next message.
	seq u64
pub:
	suite           Suite
	key             []u8
	base_nonce      []u8
	exporter_secret []u8
}

// Receiver is the receiver's decryption context, the counterpart of Sender.
pub struct Receiver {
pub mut:
	// seq is the sequence number of the next expected message.
	seq u64
pub:
	suite           Suite
	key             []u8
	base_nonce      []u8
	exporter_secret []u8
}

// check_usage verifies the SetupOpts parameter combination against the mode
// rules of RFC 9180 (section 5.1): the PSK modes require both PSK key and
// PSK identifier, the authenticated modes require the sender static key
// (sk_s on the sender side, pk_s on the receiver side), and no extraneous
// material may appear.
fn check_usage(mode u8, o SetupOpts, receiver bool) ! {
	psk_set := o.psk.len > 0
	psk_id_set := o.psk_id.len > 0
	if psk_set != psk_id_set {
		return verror('a PSK requires both a key and an identifier')
	}
	mut want_psk := false
	mut want_sender_key := false
	if mode == mode_base {
		// The base mode carries no additional material.
	} else if mode == mode_psk {
		want_psk = true
	} else if mode == mode_auth {
		want_sender_key = true
	} else if mode == mode_auth_psk {
		want_psk = true
		want_sender_key = true
	} else {
		return unsupported('unknown mode 0x${u32(mode):x02}')
	}
	if !receiver && o.pk_s.len > 0 {
		return verror('pk_s may only be set on the receiver side')
	}
	if receiver && o.sk_s.len > 0 {
		return verror('sk_s may only be set on the sender side')
	}
	if want_psk && !psk_set {
		return verror('this mode requires a PSK and its identifier')
	}
	if !want_psk && psk_set {
		return verror('this mode must not receive a PSK')
	}
	key_set := if receiver { o.pk_s.len > 0 } else { o.sk_s.len > 0 }
	if want_sender_key && !key_set {
		return verror('this mode requires the sender static key')
	}
	if !want_sender_key && key_set {
		return verror('this mode must not receive sender key material')
	}
}

// compute_nonce returns the 12-byte AEAD nonce of the seq-th message: the
// big-endian sequence count XORed into the base nonce (RFC 9180, section
// 5.2).
fn compute_nonce(base_nonce []u8, seq u64) []u8 {
	mut nonce := []u8{len: base_nonce.len}
	// The sequence count spans 8 bytes, so only the tail of the base nonce
	// changes for non-zero counters.
	tail := base_nonce.len - 8
	for i in 0 .. tail {
		nonce[i] = base_nonce[i]
	}
	for i in 0 .. 8 {
		nonce[tail + i] = base_nonce[tail + i] ^ u8(seq >> (8 * (7 - i)))
	}
	return nonce
}

// seal protects plaintext with the context: the message is encrypted under
// the AEAD nonce of the current sequence number, and the sequence advances
// by one on success (RFC 9180, section 5.2).
pub fn (mut s Sender) seal(plaintext []u8, aad []u8) ![]u8 {
	if s.suite.aead == aead_export_only {
		return unsupported('the export-only AEAD does not encrypt messages')
	}
	nonce := compute_nonce(s.base_nonce, s.seq)
	ct := chacha20poly1305.seal(s.key, nonce, plaintext, aad)!
	s.seq++
	return ct
}

// open verifies and decrypts ciphertext with the context: a success
// advances the sequence by one (RFC 9180, section 5.2). After an
// authentication failure the two sequences may have diverged, so callers
// must discard the context; the specification forbids reusing it.
pub fn (mut r Receiver) open(ciphertext []u8, aad []u8) ![]u8 {
	if r.suite.aead == aead_export_only {
		return unsupported('the export-only AEAD does not decrypt messages')
	}
	nonce := compute_nonce(r.base_nonce, r.seq)
	pt := chacha20poly1305.open(r.key, nonce, ciphertext, aad)!
	r.seq++
	return pt
}

// export derives the exporter value of the given length: a TLS-resumption
// style key export driven by the exporter secret of the context (RFC 9180,
// section 5.3).
pub fn (s Sender) export(context []u8, l int) ![]u8 {
	return export_secret(s.suite, s.exporter_secret, context, l)
}

// export derives the exporter value of the given length on the receiver
// side, identical to the sender interface.
pub fn (r Receiver) export(context []u8, l int) ![]u8 {
	return export_secret(r.suite, r.exporter_secret, context, l)
}

// setup_sender creates a sender context: it generates a fresh ephemeral key
// pair, encapsulates a shared secret to the recipient and runs the key
// schedule. It returns the encapsulated key (which the receiver needs, next
// to the ciphertexts) and the context.
pub fn (s Suite) setup_sender(mode u8, pk_r []u8, info []u8, o SetupOpts) !([]u8, Sender) {
	check_usage(mode, o, false)!
	validate_public_key(pk_r)!
	sk_em := rand.bytes(x25519.size)!
	pk_em := x25519.scalar_base(sk_em)!
	mut enc := []u8{}
	mut shared := []u8{}
	if mode == mode_auth || mode == mode_auth_psk {
		enc, shared = s.auth_encap(pk_r, sk_em, pk_em, o.sk_s)!
	} else {
		enc, shared = s.encap(pk_r, sk_em, pk_em)!
	}
	ks := s.key_schedule(mode, shared, info, o)!
	return enc, Sender{
		seq:             0
		suite:           s
		key:             ks.key
		base_nonce:      ks.base_nonce
		exporter_secret: ks.exporter_secret
	}
}

// setup_receiver creates the receiver context that decrypts the messages of
// one sender context, given the encapsulated key produced by the sender
// and the receiver's static key.
pub fn (s Suite) setup_receiver(mode u8, enc []u8, sk_r []u8, info []u8, o SetupOpts) !Receiver {
	check_usage(mode, o, true)!
	validate_public_key(enc)!
	mut shared := []u8{}
	if mode == mode_auth || mode == mode_auth_psk {
		shared = s.auth_decap(enc, sk_r, o.pk_s)!
	} else {
		shared = s.decap(enc, sk_r)!
	}
	ks := s.key_schedule(mode, shared, info, o)!
	return Receiver{
		seq:             0
		suite:           s
		key:             ks.key
		base_nonce:      ks.base_nonce
		exporter_secret: ks.exporter_secret
	}
}

// seal is the one-shot encryption form: it sets up a sender
// context, encrypts one plaintext and hands back the encapsulated key and
// the ciphertext.
pub fn (s Suite) seal(mode u8, pk_r []u8, info []u8, plaintext []u8, aad []u8, o SetupOpts) !([]u8, []u8) {
	mut enc := []u8{}
	mut ctx := Sender{}
	enc, ctx = s.setup_sender(mode, pk_r, info, o)!
	ct := ctx.seal(plaintext, aad)!
	return enc, ct
}

// open is the one-shot decryption counterpart of seal.
pub fn (s Suite) open(mode u8, enc []u8, sk_r []u8, info []u8, ciphertext []u8, aad []u8, o SetupOpts) ![]u8 {
	mut ctx := s.setup_receiver(mode, enc, sk_r, info, o)!
	return ctx.open(ciphertext, aad)
}
