![Build Status](https://img.shields.io/github/workflow/status/matrix-org/vodozemac/CI?style=flat-square)
[![codecov](https://img.shields.io/codecov/c/github/matrix-org/vodozemac/main.svg?style=flat-square)](https://codecov.io/gh/matrix-org/vodozemac)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Docs - Main](https://img.shields.io/badge/docs-main-blue.svg?style=flat-square)](https://matrix-org.github.io/vodozemac/vodozemac/index.html)
[![Docs - Stable](https://img.shields.io/crates/v/vodozemac?color=blue&label=docs&style=flat-square)](https://docs.rs/vodozemac)

A Rust implementation of Olm and Megolm

vodozemac is a Rust reimplementation of the functionality of
[libolm](https://gitlab.matrix.org/matrix-org/olm), a cryptographic library
used for end-to-end encryption in [Matrix](https://matrix.org). At its core,
vodozemac is an implementation of the Olm and Megolm cryptographic ratchets,
along with a high-level API to easily establish cryptographic communication
channels with other parties using those ratchets.

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
often documentation will shorten this to just "keys". These are:

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
use vodozemac::olm::{Account, OlmMessage, InboundCreationResult};

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
        let result = bob.create_inbound_session(alice.curve25519_key(), &m)?;

        let mut bob_session = result.session;
        let what_bob_received = result.plaintext;

        assert_eq!(alice_session.session_id(), bob_session.session_id());

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

vodozemac supports serializing its entire internal state into a form
a "pickle". The state can subsequently be restored from such a pickle
("unpickled") in order to continue operation. This is used to support some
Matrix features like device dehydration.

### Legacy pickles

The legacy pickle format is a simple binary format used by libolm. Implemented
for interoperability with current clients which are using libolm. Currently
only *unpickling* is supported.

### Modern pickles

The modern pickling mechanism used by this crate. The exact serialization
format which will be used is undecided but for now we're pickling to JSON.
Since the pickling support is based on `serde`, changing the format is easy.

The following structs support pickling:

- `Account`
- `Session`
- `GroupSession`
- `InboundGroupSession`

To pickle into a JSON string, simply call the `.pickle_to_json_string()` method,
which will return a special struct implementing `.as_str()`,
`Deref<Target=str>` and `AsRef<str>` which you can use to get to the actual
serialized string. This struct will zeroize its memory once it drops so that
any secrets within do not linger on.

For example, the following will print out the JSON representing the serialized
`Account` and will leave no new copies of the account's secrets in memory:

```rust
use anyhow::Result;
use vodozemac::olm::Account;

fn main() -> Result<()>{
    let mut account = Account::new();

    account.generate_one_time_keys(10);
    account.generate_fallback_key();

    let pickle = account.pickle_to_json_string();

    print!("{}", pickle.as_str());

    let account2 = pickle.unpickle()?;  // this is the same as `account`

    Ok(())
}
```

You can unpickle a pickle-able struct directly from its serialized form:

```rust
# use anyhow::Result;
# use vodozemac::olm::Account;
#
# fn main() -> Result<()> {
#   let some_account = Account::new();
    let json_str = some_account.pickle_to_json_string();
    let account: Account = serde_json::from_str(&json_str)?;  // the same as `some_account`
#
#    Ok(())
# }
```

However, the pickle-able structs do not implement `serde::Serialize`
themselves. If you want to serialize to a format other than JSON, you should
instead call the `.pickle()` method to obtain a special serializable struct.
This struct *does* implement `Serialize` and can therefore be serialized into
any format supported by `serde`. To get back to the original struct from such
as serializeable struct, just call `.unpickle()`.

```rust
use anyhow::Result;
use vodozemac::olm::Account;

fn main() -> Result<()> {
    let account = Account::new();
    let account: Account = account.pickle().unpickle()?;  // this is identity

    Ok(())
}
```

# Megolm

Megolm is an AES-based single ratchet for group conversations with a large
number of participants, where using Olm would be cost prohibitive because it
would imply encrypting each message individually for each participant. Megolm
sidesteps this by encrypting messages with a symmetric ratchet, shared once
with each participant and then reused for a sequence of messages before
rotating.

This is a trade-off in which we lose Olm's self-healing properties, because
someone in possession of a Megolm session at a particular state can derive all
future states. However, if the attacker is only able to obtain the session in
a ratcheted state, they cannot use it to decrypt messages encrypted with an
earlier state. This preserves forward secrecy.

A detailed technical specification can be found at
<https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>.
