A Rust implementation of Olm and Megolm

vodozemac is a Rust implementation of
[libolm](https://gitlab.matrix.org/matrix-org/olm), a cryptographic library
used for end-to-end encryption in [Matrix](https://matrix.org). At its core,
vodozemac is an implementation of the Olm and Megolm cryptographic ratchets,
along with a high-level API for easily establishing cryptographic communication
channels with other parties.

# Olm

Olm is an implementation of the [Double Ratchet
algorithm](https://whispersystems.org/docs/specifications/doubleratchet/), very
similar to that employed by the Signal Protocol. It allows the establishment of
a 1-to-1 private communication channel, with perfect forward secrecy and
self-healing properties.

A detailed technical specification can be found at
<https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>.

## Overview

The core component of the crate is the `Account`, representing a single Olm
participant. An Olm `Account` consists of a collection of key pairs, though
often documentation shortens this by just saying "keys". These are:

1. An Ed25519 *signing key pair* representing the stable cryptographic identity
   of the participant (the participant's "fingerprint").
2. A Curve25519 *sender key pair* (also sometimes called the *identity key
   pair*, somewhat confusingly).
3. A number of one-time key pairs.
4. A current and previous (if any) "fallback" key pair.

While the key in 1 is used for signing but not encryption, the keys in 2-4
participate in a triple Diffie-Hellman key exchange (3DH) with another Olm
participant, thereby establishing an Olm session on each side of the
communication channel. Ultimately, this session is used for deriving the
concrete encryption keys for a particular message.

Olm sessions are represented by the `Session` struct. Such a session is created
by calling `Account::create_outbound_session` on one of the participating
accounts, passing it the Curve25519 sender key and one Curve25519 one-time key
of the other side. The protocol is asynchronous, so the participant can start
sending messages to the other side even before the other side has created
a session, producing so-called pre-key messages (see `PreKeyMessage`).

Once the other participant receives such a pre-key message, they can create
their own matching session by calling `Account::create_inbound_session` and
passing it the pre-key message they received and the Curve25519 sender key of
the other side. This completes the establishment of the Olm communication
channel.

```rust
    use anyhow::Result;
    use vodozemac::{Account, messages::OlmMessage};

    fn main() -> Result<()> {
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let bob_otk = *bob.one_time_keys().values().next().unwrap();

        let mut alice_session = alice
            .create_outbound_session(*bob.curve25519_key(), bob_otk);

        bob.mark_keys_as_published();

        let message = "Keep it between us, OK?";
        let alice_msg = alice_session.encrypt(message);

        if let OlmMessage::PreKey(m) = alice_msg.clone() {
            let mut bob_session = bob
                .create_inbound_session(alice.curve25519_key(), &m)?;

            assert_eq!(alice_session.session_id(), bob_session.session_id());

            let what_bob_received = bob_session.decrypt(&alice_msg)?;
            assert_eq!(message, what_bob_received);

            let bob_reply = "Yes. Take this, it's dangerous out there!";
            let bob_encrypted_reply = bob_session.encrypt(bob_reply).into();

            let what_alice_received = alice_session
                .decrypt(&bob_encrypted_reply)?;
            assert_eq!(&what_alice_received, bob_reply);
        }

        Ok(())
    }
```

## Sending messages

To encrypt a message, just call `Session::encrypt(msg_content)`. This will
either produce an `OlmMessage::PreKey(..)` or `OlmMessage::Normal(..)`
depending on whether the session is fully established. A session is fully
established once you receive (and decrypt) at least one message from the other
side.

## Pickling

vodozemac (*will soon*) supports pickling of both `Account` and `Session`, in
which the entire state contained within is serialized into a form called
a "pickle". Subsequently, accounts and sessions can be restored from a pickle
("unpickled") in order to continue operation. This is used to support some
Matrix features like device dehydration.

### Legacy pickles

The legacy pickle format is a simple binary format used by libolm. Currently
*unimplemented*, but will need to be implemented for interoperability with
legacy clients using libolm.

### Modern pickles

The pickle format used by this crate. The exact format is currently undecided,
but is likely to be based on Protocol Buffers. For now, we're pickling to JSON.
Also *unimplemented* at the moment in the repository but will be added shortly.

# Megolm

Megolm is an AES-based single ratchet for group conversations with a large
number of participants, where using Olm would be cost prohibitive, (because it
would imply establishing a pairwise channel between each pair of participants).

This is a trade-off in which we lose Olm's self-healing properties, because
someone in possession of a Megolm session at a particular state can derive all
future states. However, if the attacker is only able to obtain the session in
a ratcheted state, they cannot use it to decrypt messages encrypted with an
earlier state. This preserves forward secrecy.

A detailed technical specification can be found at
<https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>.

# Vendored libraries

vodozemac currently vendors `olm-rs` to provide a fixed version of the SAS MAC
calculation method, `calculate_mac_fixed_base64`. This is used solely for
implementing correctness tests against libolm and will be removed once the
fixed method has been exposed in upstream `olm-rs`.
