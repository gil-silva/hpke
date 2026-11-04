# hpke

HPKE public key encryption (RFC 9180), in pure V: the X25519 DH KEM
(composed with `gil_silva.x25519`), the HKDF-based context KDF over the
standard library and the ChaCha20-Poly1305 AEAD (composed with
`gil_silva.chacha20poly1305`), for all four protocol modes, plus the
export-only AEAD (0xffff).

No `unsafe` blocks; every fallible path returns a V result. The module is
checked against the official RFC 9180 test vectors — see
[Verification](#verification) or run `v test .`.

## Usage

### Encrypt and decrypt (one-shot)

```v
import gil_silva.hpke

fn main() {
	// One cipher suite: the X25519 KEM with the HKDF-SHA256 context KDF
	// and the ChaCha20-Poly1305 AEAD.
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!

	// The receiver publishes pk_r (32 bytes) and keeps sk_r secret; the
	// encapsulated key enc travels next to the ciphertext on the wire.
	sk_r, pk_r := hpke.generate_key_pair()!
	println('pk_r: ${pk_r.len} bytes')

	// The one-shot form: seal returns the encapsulated key and the
	// ciphertext in one call. The info string binds the protocol context
	// into the key schedule, the aad bytes into every ciphertext.
	info := 'demo protocol'.bytes()
	enc, ct := suite.seal(hpke.mode_base, pk_r, info, 'hello hpke'.bytes(), 'aad'.bytes(), hpke.SetupOpts{})!
	println('seal: enc=${enc.len} bytes, ct=${ct.len} bytes')

	// The receiver opens with its static key.
	pt := suite.open(hpke.mode_base, enc, sk_r, info, ct, 'aad'.bytes(), hpke.SetupOpts{})!
	assert pt.bytestr() == 'hello hpke'
	println('open: decrypted in one call')
}
```

### Contexts and sequence numbers

The one-shot form encrypts exactly one message per call. A `Sender`/`Receiver`
context pair runs the key schedule once and then protects any number of
messages, each under its own AEAD nonce derived from the big-endian sequence
count XORed into the base nonce:

```v
import gil_silva.hpke

fn main() {
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!
	sk_r, pk_r := hpke.generate_key_pair()!
	info := 'app'.bytes()

	// The context form: setup_sender generates the ephemeral key pair and
	// runs the key schedule once, then protects every message under its
	// own AEAD nonce derived from the sequence number.
	enc, mut sender := suite.setup_sender(hpke.mode_base, pk_r, info, hpke.SetupOpts{})!
	mut receiver := suite.setup_receiver(hpke.mode_base, enc, sk_r, info, hpke.SetupOpts{})!

	ct := sender.seal('first message'.bytes(), 'aad'.bytes())!
	pt := receiver.open(ct, 'aad'.bytes())!
	assert pt.bytestr() == 'first message'
	ct2 := sender.seal('second message'.bytes(), []u8{})!
	pt2 := receiver.open(ct2, []u8{})!
	assert pt2.bytestr() == 'second message'

	// The sequence numbers advance in lockstep.
	println('sender.seq=${sender.seq}, receiver.seq=${receiver.seq}')

	// Both sides derive the same independent secrets through the
	// exporter interface.
	left := sender.export('key exchange demo'.bytes(), 32)!
	assert left == receiver.export('key exchange demo'.bytes(), 32)!
	println('exporter values agree (${left.len} bytes)')

	// A replayed ciphertext fails: the receiver computes its nonce from
	// the current sequence count, so the AEAD tag never fits.
	replay := receiver.open(ct2, []u8{}) or {
		println('replay refused: ${err}')
		[]u8{}
	}
	_ = replay
}
```

### PSK mode

The PSK mode mixes an out-of-band secret and its identifier into the key
schedule, on top of the KEM shared secret. Both sides must carry the same
`SetupOpts` parts:

```v
import gil_silva.hpke

fn main() {
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!
	sk_r, pk_r := hpke.generate_key_pair()!
	info := 'psk demo'.bytes()
	aad := 'aad'.bytes()

	// The PSK modes combine the KEM shared secret with an out-of-band
	// secret. Both sides carry the same SetupOpts parts: psk and psk_id.
	opts := hpke.SetupOpts{
		psk:    'out of band random key'.bytes()
		psk_id: 'psk demo 1'.bytes()
	}
	enc, ct := suite.seal(hpke.mode_psk, pk_r, info, 'psk protected message'.bytes(), aad, opts)!
	println('psk seal: enc=${enc.len} bytes, ct=${ct.len} bytes')

	// The receiver carries the same PSK material.
	pt := suite.open(hpke.mode_psk, enc, sk_r, info, ct, aad, opts)!
	assert pt.bytestr() == 'psk protected message'
	println('psk round trip OK')

	// A receiver with a different PSK drives a different key schedule,
	// so the ciphertext fails authentication.
	wrong := hpke.SetupOpts{
		psk:    'a different random key'.bytes()
		psk_id: 'psk demo 1'.bytes()
	}
	out := suite.open(hpke.mode_psk, enc, sk_r, info, ct, aad, wrong) or {
		println('wrong psk refused: ${err}')
		[]u8{}
	}
	_ = out
}
```

### Authenticated sender

The authenticated modes add the sender's static X25519 key pair: its DH
contribution is folded into the shared secret and the key schedule context
carries the sender's public key, so ciphertexts are bound to the sender
identity. The sender side carries `sk_s`, the receiver side carries the
published `pk_s`:

```v
import gil_silva.hpke

fn main() {
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!
	sk_r, pk_r := hpke.generate_key_pair()!
	info := 'auth demo'.bytes()
	aad := 'aad'.bytes()

	// The authenticated modes add the sender's static X25519 key: the DH
	// contribution of sk_s joins the shared secret, so the ciphertext is
	// bound to the sender identity. The sender side carries sk_s in the
	// options; the receiver side carries the published pk_s.
	sk_s, pk_s := hpke.generate_key_pair()!
	sender_opts := hpke.SetupOpts{
		sk_s: sk_s
	}
	enc, ct := suite.seal(hpke.mode_auth, pk_r, info, 'authenticated sender'.bytes(), aad, sender_opts)!
	println('auth seal: enc=${enc.len} bytes, ct=${ct.len} bytes')

	receiver_opts := hpke.SetupOpts{
		pk_s: pk_s
	}
	pt := suite.open(hpke.mode_auth, enc, sk_r, info, ct, aad, receiver_opts)!
	assert pt.bytestr() == 'authenticated sender'
	println('auth round trip OK with the right sender key')

	// A receiver that trusts a different sender key refuses the message:
	// the key schedule folds pk_s in, so authentication fails.
	out := suite.open(hpke.mode_auth, enc, sk_r, info, ct, aad, hpke.SetupOpts{
		pk_s: pk_r
	}) or {
		println('wrong sender key refused: ${err}')
		[]u8{}
	}
	_ = out
}
```

### The exporter interface

Every context exposes an exporter that derives independent secrets from the
context's exporter secret — TLS-resumption style:

```v
import gil_silva.hpke

fn main() {
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!
	sk_r, pk_r := hpke.generate_key_pair()!
	info := 'tls demo'.bytes()

	// The exporter interface derives independent secrets from the
	// context, TLS-resumption style: both sides call export with a
	// context string and an output length, and agree on every value.
	enc, mut sender := suite.setup_sender(hpke.mode_base, pk_r, info, hpke.SetupOpts{})!
	receiver := suite.setup_receiver(hpke.mode_base, enc, sk_r, info, hpke.SetupOpts{})!

	engine_key := sender.export('engine key'.bytes(), 32)!
	assert engine_key == receiver.export('engine key'.bytes(), 32)!
	println('exporter: ${engine_key.len} bytes on both sides')

	// The requested length must be between 1 and 65535 bytes.
	out := sender.export('engine key'.bytes(), 0) or {
		println('size 0 rejected: ${err}')
		[]u8{}
	}
	_ = out
	smallest := sender.export('engine key'.bytes(), 1)!
	println('size 1 ok: ${smallest.len} byte')
}
```

The cap: the suite's HKDF-Expand derives at most `255 * Nh` bytes, where `Nh`
is the output size of the suite KDF's hash (8160 for HKDF-SHA256, 16320 for
HKDF-SHA512). Sizes within `1..65535` but past the cap fail with a
`ValidationError` too.

### Error taxonomy

The module distinguishes unsupported protocol parameters from invalid inputs,
and inherits the AEAD authentication failure (a replayed or corrupted
ciphertext, or a PSK/sender-key mismatch) from `chacha20poly1305`:

```v
import gil_silva.hpke

fn main() {
	suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_chacha20poly1305)!
	sk_r, pk_r := hpke.generate_key_pair()!

	// Unknown KDF and AEAD identifiers fail at construction; in
	// particular the AES-GCM suites are not implemented in pure V.
	mut unsupported := false
	trash := hpke.new_suite(hpke.kdf_sha512, u16(0x0001)) or {
		unsupported = err is hpke.UnsupportedError
		hpke.Suite{}
	}
	_ = trash
	assert unsupported
	println('AES-GCM rejected as unsupported')

	// Protocol inputs are validated: X25519 key material is framed in
	// exactly 32 bytes.
	mut framed := false
	bad := suite.open(hpke.mode_base, []u8{len: 31}, sk_r, []u8{}, []u8{}, []u8{}, hpke.SetupOpts{}) or {
		framed = err is hpke.ValidationError
		[]u8{}
	}
	_ = bad
	assert framed
	println('31-byte enc rejected as invalid')

	// The export-only AEAD (0xffff) protects no messages: seal and open
	// refuse, while the exporter interface stays available and the
	// context carries no key and no base nonce.
	export_suite := hpke.new_suite(hpke.kdf_sha256, hpke.aead_export_only)!
	enc, mut sender := export_suite.setup_sender(hpke.mode_base, pk_r, 'export demo'.bytes(), hpke.SetupOpts{})!
	println('export-only sender: enc=${enc.len} bytes, key=${sender.key.len} bytes, base_nonce=${sender.base_nonce.len} bytes')

	mut refused := false
	ct := sender.seal('hidden message'.bytes(), []u8{}) or {
		refused = err is hpke.UnsupportedError
		[]u8{}
	}
	_ = ct
	assert refused
	println('export-only seal refused')

	ex := sender.export('exported anyway'.bytes(), 32)!
	println('export-only export: ${ex.len} bytes')
}
```

## API

The module lives in three files:

| File | Contents |
|---|---|
| `hpke.v` | the suite (`new_suite`), the protocol modes and constants, `SetupOpts`, the `Sender`/`Receiver` contexts with `seal`/`open`/`export` and the one-shot `Suite.seal`/`Suite.open` |
| `kem.v` | the X25519 DH KEM: `generate_key_pair`, `derive_key_pair`, `(auth_)encap`/`(auth_)decap` |
| `kdf.v` | the labeled HKDF layer (`LabeledExtract`/`LabeledExpand`), the context key schedule and the exporter |

The main entry points:

| Symbol | Role |
|---|---|
| `new_suite(kdf, aead)` | validate and build a suite over the X25519 KEM (`kem_id_x25519` is fixed) |
| `generate_key_pair()` | fresh random `(sk, pk)` X25519 pair |
| `derive_key_pair(ikm)` | deterministic KEM key derivation (RFC 9180, section 7.1.3) |
| `suite.seal(mode, pk_r, info, plaintext, aad, opts)` | one-shot encrypt, returns `(enc, ciphertext)` |
| `suite.open(mode, enc, sk_r, info, ciphertext, aad, opts)` | one-shot decrypt |
| `suite.setup_sender(mode, pk_r, info, opts)` | returns `(enc, Sender)` |
| `suite.setup_receiver(mode, enc, sk_r, info, opts)` | returns `Receiver` |
| `sender.seal(pt, aad)` / `receiver.open(ct, aad)` | per-message protect, advancing `seq` |
| `sender/exporter .export(context, l)` | derive `l` bytes over an exporter context |
| `mode_base`, `mode_psk`, `mode_auth`, `mode_auth_psk` | protocol modes |
| `kdf_sha256`, `kdf_sha512` | context KDF identifiers |
| `aead_chacha20poly1305`, `aead_export_only` | AEAD identifiers |
| `SetupOpts{ psk, psk_id, sk_s, pk_s }` | mode parameters: PSK parts and the sender static key |

### Errors

| Type | Raised by | Meaning |
|---|---|---|
| `UnsupportedError` | `new_suite`, `seal`/`open` | unknown mode, KDF or AEAD identifier, or an operation the export-only AEAD cannot provide; the AES-GCM suites fall here (not implemented in pure V) |
| `ValidationError` | setup, export | invalid inputs: key material not exactly 32 bytes, incomplete or extraneous PSK/sender-key usage, export sizes outside 1..65535 or past the suite KDF's HKDF-Expand limit (255 * Nh) |
| `chacha20poly1305.AuthenticationError` | `open` | ciphertext does not authenticate (corruption, replay, wrong receiver context) |
| `x25519.{LengthError,LowOrderPointError}` | KEM | malformed key material or a low order point |

The distinction that matters to callers: an `AuthenticationError` means the
bytes arrived but were not produced by the intended other side; a
`ValidationError` means the input violates the protocol framing before any
cryptographic material is used. Contexts must be discarded after an
authentication failure, because sender and receiver sequence numbers may have
diverged.

## Verification

`v test .` runs the module against the official RFC 9180 test vectors
(the full set from
https://github.com/cfrg/draft-irtf-cfrg-hpke, vendored and filtered to
`testkit/hpke_x25519.json`): the 16 vectors with the X25519 KEM over the
combinations this module implements — HKDF-SHA256/SHA512 x
ChaCha20-Poly1305 and export-only, all four modes. For every vector the
tests check the deterministic key derivation (every `ikmE`/`ikmR`/`ikmS`
reproduces its recorded key material), the KEM encapsulation and its
authenticated variant against the recorded `enc` and `shared_secret`
(the KEM labels match the draft's `eae_prk` composition), every key
schedule field (`key`, `base_nonce`, `exporter_secret`), all 8 ciphertext
records with their nonces and sequence numbers and all 3 exporter records.

On top of the vectors, the tests cover random-seeded roundtrips (both KDFs,
context and one-shot forms, multi-message sequences) and the rejection
behavior (suite/mode/PSK/sender-key rules, key length framing, export size
bounds).

## Install

Once the modules are registered on vpm:

```sh
v install gil-silva.hpke
```

This installs the `hpke` module together with its dependencies
(`gil-silva.x25519`, `gil-silva.chacha20poly1305`), and the import path is
`import gil_silva.hpke` (qualification stays `hpke.*`).

## License

MIT, see [LICENSE](LICENSE).
