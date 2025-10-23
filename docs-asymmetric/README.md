#  Add a new device with ECC keys

You can encrypt your existing AES key to a new
device’s X25519 public key. The standard way is to use a
[KEM-style](https://soatok.blog/2024/02/26/kem-trails-understanding-key-encapsulation-mechanisms/)
construction with X25519 (not bare DH by itself) such as HPKE (RFC 9180).
Use KEM (X25519 + HKDF) to derive a one-time key-encryption key (KEK),
then AEAD-encrypt (“wrap”) the AES key for that device.


## How it maps conceptually

__RSA world__: Public-key encryption of a random content key (your AES key) for
each device.

__ECC (X25519) world__: Use a KEM (key encapsulation mechanism).

* Generate an ephemeral X25519 keypair.
* Do ECDH with the recipient’s static X25519 public key, derive a shared secret.
* Run HKDF to derive a KEK.
* AEAD-encrypt your AES key (e.g., AES-GCM or ChaCha20-Poly1305) under that KEK.
* Store/transmit the AEAD ciphertext plus the KEM “encapsulation”
  (the ephemeral pubkey).

The recipient uses their static private key + your ephemeral pubkey to rederive
the KEK and decrypt the wrapped AES key.

This is exactly what HPKE specifies (e.g., DHKEM(X25519, HKDF-SHA256) + AES-GCM
or ChaCha20-Poly1305). It’s also the idea behind libsodium’s sealed boxes and
tools like age: you make a fresh encapsulation per recipient.


## Key-Wrapping (most common for stored data)

Keep a long-lived __content key__ (AES) for your dataset/group.

For each device D, store a __wrap entry__:

```yml
recipients: [
  { device_id: D1, enc: hpke_enc1, wrapped_key: aead_ct1 },
  { device_id: D2, enc: hpke_enc2, wrapped_key: aead_ct2 },
  ...
]
```

* Add device: run HPKE with the new device’s X25519 public key, produce
  `{ enc, wrapped_key }` and append it. No re-encrypting the data blob—just add
  another recipient entry.
* Remove device / rotate: rotate the content key and rewrap for
  remaining devices.


This mirrors “hybrid RSA + AES,” but with X25519 HPKE instead of RSA-OAEP.


### Gotchas / best practices

Use an AEAD (AES-GCM or ChaCha20-Poly1305). Don’t “just” encrypt &mdash; get
integrity too.

Version & bind associated data (key IDs, algorithm suite, content key version)
in AEAD AAD.

Rotate on membership changes if forward secrecy matters.

Authenticate the sender if needed (HPKE has modes that add sender auth;
libsodium crypto_box does sender-auth).

Don’t reuse nonces; frameworks like HPKE handle nonce derivation for you.


### Bottom line

RSA encryption (wrap a symmetric key per device) translates directly to
X25519 using HPKE/ECIES-style wrapping. That’s the standard practice
for *add a device* when the goal is to grant access to existing encrypted data
without re-encrypting the whole dataset.

For messaging protocols, use a session (X3DH/DR or MLS) and send/rotate group
keys as the protocol prescribes.
