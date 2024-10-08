# Changelog

All notable changes to this project will be documented in this file.

## [0.8.1] - 2024-10-08

### Bug Fixes

- Fix the compilation when the default features are disabled


## 0.8.0 - 2024-09-20

### Features

- Apply the const keyword to many methods ([#167](https://github.com/matrix-org/vodozemac/pull/167)).

- [**BREAKING**] The `Account::sign()` method now accepts an `impl AsRef<[u8]>`
for the message instead of a `&str`. This has been streamlined to be like
most of our other methods accepting a message to be encrypted. This
change is mostly backwards compatible as the method will continue to
accept a string.

The `OlmMessage::from_parts()` and `OlmMessage::to_parts()` methods now
accept and return an `&[u8]` and `Vec<u8>` exclusively for the
ciphertext. The `base64_encode()` and `base64_decode()` methods can be
used to achieve the previous behavior ([#176](https://github.com/matrix-org/vodozemac/pull/176)).

- Add support for the libolm PkEncryption feature. This allows
Matrix clients to implement the [m.megolm_backup.v1.curve25519-aes-sha2](https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2)
room key backup algorithm. Please note that this algorithm contains a
critical flaw and should only be used for compatibility reasons ([#171](https://github.com/matrix-org/vodozemac/pull/171)) ([#180](https://github.com/matrix-org/vodozemac/pull/180)).

### Refactor

- Remove the pkcs7 crate from the list of dependencies ([#164](https://github.com/matrix-org/vodozemac/pull/164)).

- Remove Debug implementations for the libolm compat structs ([#184](https://github.com/matrix-org/vodozemac/pull/184)).

## 0.7.0 - 2024-07-17

### Features

- Add an [Elliptic Curve Integrated Encryption
  Scheme](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme). This
  scheme can be used to establish a secure *ephemeral* encrypted channel, in
  situations for which Olm may be unsuitable due to complexity or the
  unavailability of long-term identity keys. There is also support for
  out-of-band authentication of the receiver side. The scheme was designed
  primarily for purposes of implementing Matrix QR code login.
  ([#151](https://github.com/matrix-org/vodozemac/pull/151)).

### Security

- Use a constant-time Base64 encoder for secret key material to mitigate
  side-channel attacks leaking secret key material ([#156](https://github.com/matrix-org/vodozemac/pull/156)) (Low, [CVE-2024-40640](https://www.cve.org/CVERecord?id=CVE-2024-40640), [GHSA-j8cm-g7r6-hfpq](https://github.com/matrix-org/vodozemac/security/advisories/GHSA-j8cm-g7r6-hfpq)).

## [0.6.0] - 2024-05-06

### Security Fixes

- Re-enable zeroization in the Dalek crates ([#130](https://github.com/matrix-org/vodozemac/pull/130)) (Low, [CVE-2024-34063](https://www.cve.org/CVERecord?id=CVE-2024-34063), [GHSA-c3hm-hxwf-g5c6](https://github.com/matrix-org/vodozemac/security/advisories/GHSA-c3hm-hxwf-g5c6))


### Features

- Track the number of Diffie-Hellman ratchet advances in the Olm Session.
  This number is useful only for debugging purposes and will be included in the
  Debug output of the Olm `Session` ([#134](https://github.com/matrix-org/vodozemac/pull/134)).

### Testing

- Add mutation tests ([#136](https://github.com/matrix-org/vodozemac/pull/136)) ([#138](https://github.com/matrix-org/vodozemac/pull/138)) ([#140](https://github.com/matrix-org/vodozemac/pull/140)) ([#139](https://github.com/matrix-org/vodozemac/pull/139)) ([#144](https://github.com/matrix-org/vodozemac/pull/144)) ([#143](https://github.com/matrix-org/vodozemac/pull/143)),
  special thanks to [Johannes Marbach](https://github.com/Johennes) for that.
- Enable mutation tests on CI ([#147](https://github.com/matrix-org/vodozemac/pull/147)).

## [0.5.1] - 2024-02-05

### Features

- Include the ratchet key in the Debug output of the Session

## [0.5.0] - 2023-10-06

### Features

- Add support for exporting an Account to a libolm pickle ([#111](https://github.com/matrix-org/vodozemac/pull/111))
- Add base64 decoding and encoding methods to the public interface ([#112](https://github.com/matrix-org/vodozemac/pull/112))


## [0.4.0] - 2023-05-31

### Bug Fixes

- Use the next key id from the libolm pickle instead of guessing

### Features

- Add a prettier display/debug implementation for Ed25519Signature
- Introduce an upgrade method to the InboundGroupSession struct
- Expose the version of vodozemac
- Make Debug representation of the public key types prettier
- Add a method to calculate the Session ID from a pre-key message
- [**breaking**] Return the created and discarded one-time keys when generating new ones ([#100](https://github.com/matrix-org/vodozemac/pull/100))
- [**breaking**] Return the fallback key which was removed when generating a new one
- Expose the build-time git commit hash and description as static vars
- Expose the Curve25519SecretKey type

### Refactor

- Rename the key_id field to next_key_id for clarity
- Use the matrix-pickle crate for libolm unpickling support

### Testing

- Ensure signing_key_verified is handled when upgrading.

## [0.3.0] - 2022-09-13

### Bug Fixes

- Accept a byteslice for the pickle key
- Hide the remove_one_time_key method
- Abort unpickling if we have too many one-time keys
- Use overflowing addition when incrementing key ids

### Documentation

- Fix some typos and improve the InboundGroupSession docs
- Clarify wording in OTK comment

### Features

- Add Debug and PartialEq implementations to MegolmMessage
- Add a bunch of missing Eq imlpementations
- Add TryFrom implementations for session keys
- Allow GroupSessions to be unpickled from libolm pickles
- Encode/decode bytes directly in Olm (no string wrapping)
- Encode/decode bytes directly in megolm (no string wrapping)
- Allow megolm messages to be cloned
- Add a method to check if two inbound group sessions are connected
- Add a method to compare two inbound group sessions
- Add support to not truncate MAC tags when encrypting messages
- Implement Display for the public key types
- Implement zeroize for the SessionKey

### Refactor

- Remove the encoded public key from the curve25519 types
- Remove the encoded public key methods
- Remove the encoded one-time keys method
- Create a LibolmEd25519Keypair struct
- Move the libolm RatchetPickle to a common module
- Move the libolm unpickling structs out of the method
- Improve the Debug implementation for SessionKeys
- Refrain from repeating method call.
- Group the session key methods correctly

<!-- generated by git-cliff -->
