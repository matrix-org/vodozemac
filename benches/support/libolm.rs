//! Hand-rolled bindings for the libolm operations the benchmarks compare.
//!
//! [`olm_rs`] is a safe wrapper around libolm and copies data in and out of
//! `String`s on every call. This module calls the same libolm entry points
//! through [`olm_sys`] directly, without those copies, so that the benchmarks
//! can separate the cost of the bindings from the cost of libolm itself.
//!
//! The wrappers here are deliberately minimal: they allocate the buffers
//! libolm asks for, make the call, and check the return value. They are only
//! meant to be driven by the benchmarks in this directory, so failures panic
//! instead of being reported.

use rand::{Rng, rng};
use zeroize::Zeroizing;

/// The type of an Olm message, as libolm numbers them.
pub(crate) type MessageType = usize;

/// A pre-key Olm message.
pub(crate) const MESSAGE_TYPE_PRE_KEY: MessageType = olm_sys::OLM_MESSAGE_TYPE_PRE_KEY;

/// Fill a buffer with the random bytes libolm asks for.
fn random_bytes(length: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    rng().fill_bytes(&mut bytes);

    bytes
}

/// Check the return value of a libolm call.
fn check(result: usize, message: &str) -> usize {
    // SAFETY: `olm_error()` takes no arguments and only returns the sentinel
    // value libolm uses to signal errors.
    let error = unsafe { olm_sys::olm_error() };

    assert_ne!(result, error, "{message}");

    result
}

/// A libolm `OlmAccount`.
pub(crate) struct Account {
    // The pointer below points into this buffer, so it must not be resized.
    _buffer: Box<[u8]>,
    ptr: *mut olm_sys::OlmAccount,
}

impl Account {
    /// Allocate the memory libolm wants for an account and initialise it.
    fn allocate() -> Self {
        // SAFETY: `olm_account_size()` takes no arguments, and `olm_account()`
        // initialises an account in the buffer we hand it, which is at least
        // `olm_account_size()` bytes long and outlives the account.
        unsafe {
            let mut buffer = vec![0u8; olm_sys::olm_account_size()].into_boxed_slice();
            let ptr = olm_sys::olm_account(buffer.as_mut_ptr().cast());

            Self { _buffer: buffer, ptr }
        }
    }

    /// Create a new account.
    pub(crate) fn new() -> Self {
        let account = Self::allocate();

        // SAFETY: `account.ptr` is an initialised account and the random buffer
        // is as long as libolm asked for.
        unsafe {
            let mut random = random_bytes(olm_sys::olm_create_account_random_length(account.ptr));

            check(
                olm_sys::olm_create_account(account.ptr, random.as_mut_ptr().cast(), random.len()),
                "libolm should be able to create an account",
            );
        }

        account
    }

    /// Restore an account from a pickle encrypted with the given key.
    ///
    /// The pickle is consumed since libolm destroys the input buffer.
    pub(crate) fn from_pickle(mut pickle: Vec<u8>, pickle_key: &[u8]) -> Self {
        let account = Self::allocate();

        // SAFETY: `account.ptr` is an initialised account and both the key and
        // the pickle are valid for the lengths we pass along with them.
        unsafe {
            check(
                olm_sys::olm_unpickle_account(
                    account.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    pickle.len(),
                ),
                "libolm should be able to decrypt the account pickle",
            );
        }

        account
    }

    /// Pickle the account, encrypting it with the given key.
    pub(crate) fn pickle(&self, pickle_key: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised account and the output buffer is
        // `olm_pickle_account_length()` bytes long.
        unsafe {
            let length = olm_sys::olm_pickle_account_length(self.ptr);
            let mut pickle = vec![0u8; length];

            check(
                olm_sys::olm_pickle_account(
                    self.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to pickle the account",
            );

            pickle
        }
    }

    /// Generate `count` new one-time keys.
    pub(crate) fn generate_one_time_keys(&mut self, count: usize) {
        // SAFETY: `self.ptr` is an initialised account and the random buffer is
        // as long as libolm asked for.
        unsafe {
            let length = olm_sys::olm_account_generate_one_time_keys_random_length(self.ptr, count);
            let mut random = random_bytes(length);

            check(
                olm_sys::olm_account_generate_one_time_keys(
                    self.ptr,
                    count,
                    random.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to generate one-time keys",
            );
        }
    }

    /// Sign a message with the account's Ed25519 key.
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised account and the signature buffer
        // is `olm_account_signature_length()` bytes long.
        unsafe {
            let length = olm_sys::olm_account_signature_length(self.ptr);
            let mut signature = vec![0u8; length];

            check(
                olm_sys::olm_account_sign(
                    self.ptr,
                    message.as_ptr().cast(),
                    message.len(),
                    signature.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to sign a message",
            );

            signature
        }
    }

    /// Create an outbound session to the given published keys.
    pub(crate) fn create_outbound_session(
        &self,
        their_identity_key: &[u8],
        their_one_time_key: &[u8],
    ) -> Session {
        let session = Session::allocate();

        // SAFETY: both pointers are initialised, the keys are valid for the
        // lengths we pass along with them and the random buffer is as long as
        // libolm asked for.
        unsafe {
            let mut random =
                random_bytes(olm_sys::olm_create_outbound_session_random_length(session.ptr));

            check(
                olm_sys::olm_create_outbound_session(
                    session.ptr,
                    self.ptr,
                    their_identity_key.as_ptr().cast(),
                    their_identity_key.len(),
                    their_one_time_key.as_ptr().cast(),
                    their_one_time_key.len(),
                    random.as_mut_ptr().cast(),
                    random.len(),
                ),
                "libolm should be able to create an outbound session",
            );
        }

        session
    }

    /// Create an inbound session from a pre-key message.
    ///
    /// The message is consumed since libolm destroys the input buffer.
    pub(crate) fn create_inbound_session(
        &mut self,
        their_identity_key: &[u8],
        mut pre_key_message: Vec<u8>,
    ) -> Session {
        let session = Session::allocate();

        // SAFETY: both pointers are initialised and the key and the message are
        // valid for the lengths we pass along with them.
        unsafe {
            check(
                olm_sys::olm_create_inbound_session_from(
                    session.ptr,
                    self.ptr,
                    their_identity_key.as_ptr().cast(),
                    their_identity_key.len(),
                    pre_key_message.as_mut_ptr().cast(),
                    pre_key_message.len(),
                ),
                "libolm should be able to create an inbound session",
            );
        }

        session
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is an initialised account that isn't used again.
        unsafe {
            olm_sys::olm_clear_account(self.ptr);
        }
    }
}

/// A libolm `OlmSession`.
pub(crate) struct Session {
    // The pointer below points into this buffer, so it must not be resized.
    _buffer: Box<[u8]>,
    ptr: *mut olm_sys::OlmSession,
}

impl Session {
    /// Allocate the memory libolm wants for a session and initialise it.
    fn allocate() -> Self {
        // SAFETY: `olm_session_size()` takes no arguments, and `olm_session()`
        // initialises a session in the buffer we hand it, which is at least
        // `olm_session_size()` bytes long and outlives the session.
        unsafe {
            let mut buffer = vec![0u8; olm_sys::olm_session_size()].into_boxed_slice();
            let ptr = olm_sys::olm_session(buffer.as_mut_ptr().cast());

            Self { _buffer: buffer, ptr }
        }
    }

    /// Restore a session from a pickle encrypted with the given key.
    ///
    /// The pickle is consumed since libolm destroys the input buffer.
    pub(crate) fn from_pickle(mut pickle: Vec<u8>, pickle_key: &[u8]) -> Self {
        let session = Self::allocate();

        // SAFETY: `session.ptr` is an initialised session and both the key and
        // the pickle are valid for the lengths we pass along with them.
        unsafe {
            check(
                olm_sys::olm_unpickle_session(
                    session.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    pickle.len(),
                ),
                "libolm should be able to decrypt the session pickle",
            );
        }

        session
    }

    /// Encrypt a message.
    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session, the plaintext is valid
        // for the length we pass along with it and both the random and the
        // message buffer are as long as libolm asked for.
        unsafe {
            let length = olm_sys::olm_encrypt_message_length(self.ptr, plaintext.len());
            let mut message = vec![0u8; length];
            let mut random = random_bytes(olm_sys::olm_encrypt_random_length(self.ptr));

            check(
                olm_sys::olm_encrypt(
                    self.ptr,
                    plaintext.as_ptr().cast(),
                    plaintext.len(),
                    random.as_mut_ptr().cast(),
                    random.len(),
                    message.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to encrypt a message",
            );

            message
        }
    }

    /// Decrypt a message.
    ///
    /// The message is consumed since libolm destroys the input buffer. It gets
    /// copied once because the length of the plaintext has to be queried
    /// first, which destroys the buffer as well.
    pub(crate) fn decrypt(&mut self, message_type: MessageType, mut message: Vec<u8>) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session, both message buffers
        // are valid for the lengths we pass along with them and the plaintext
        // buffer is as long as libolm asked for.
        unsafe {
            let mut message_for_length = message.clone();

            let length = check(
                olm_sys::olm_decrypt_max_plaintext_length(
                    self.ptr,
                    message_type,
                    message_for_length.as_mut_ptr().cast(),
                    message_for_length.len(),
                ),
                "libolm should be able to tell us the plaintext length",
            );

            let mut plaintext = vec![0u8; length];

            let length = check(
                olm_sys::olm_decrypt(
                    self.ptr,
                    message_type,
                    message.as_mut_ptr().cast(),
                    message.len(),
                    plaintext.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to decrypt the message",
            );

            plaintext.truncate(length);

            plaintext
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is an initialised session that isn't used again.
        unsafe {
            olm_sys::olm_clear_session(self.ptr);
        }
    }
}

/// A libolm `OlmOutboundGroupSession`.
pub(crate) struct GroupSession {
    // The pointer below points into this buffer, so it must not be resized.
    _buffer: Box<[u8]>,
    ptr: *mut olm_sys::OlmOutboundGroupSession,
}

impl GroupSession {
    /// Allocate the memory libolm wants for an outbound group session and
    /// initialise it.
    fn allocate() -> Self {
        // SAFETY: `olm_outbound_group_session_size()` takes no arguments, and
        // `olm_outbound_group_session()` initialises a session in the buffer we
        // hand it, which is at least `olm_outbound_group_session_size()` bytes
        // long and outlives the session.
        unsafe {
            let mut buffer =
                vec![0u8; olm_sys::olm_outbound_group_session_size()].into_boxed_slice();
            let ptr = olm_sys::olm_outbound_group_session(buffer.as_mut_ptr().cast());

            Self { _buffer: buffer, ptr }
        }
    }

    /// Create a new outbound group session.
    pub(crate) fn new() -> Self {
        let session = Self::allocate();

        // SAFETY: `session.ptr` is an initialised session and the random buffer
        // is as long as libolm asked for.
        unsafe {
            let length = olm_sys::olm_init_outbound_group_session_random_length(session.ptr);
            let mut random = random_bytes(length);

            check(
                olm_sys::olm_init_outbound_group_session(session.ptr, random.as_mut_ptr(), length),
                "libolm should be able to create an outbound group session",
            );
        }

        session
    }

    /// Restore an outbound group session from a pickle encrypted with the given
    /// key.
    ///
    /// The pickle is consumed since libolm destroys the input buffer.
    pub(crate) fn from_pickle(mut pickle: Vec<u8>, pickle_key: &[u8]) -> Self {
        let session = Self::allocate();

        // SAFETY: `session.ptr` is an initialised session and both the key and
        // the pickle are valid for the lengths we pass along with them.
        unsafe {
            check(
                olm_sys::olm_unpickle_outbound_group_session(
                    session.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    pickle.len(),
                ),
                "libolm should be able to decrypt the group session pickle",
            );
        }

        session
    }

    /// Pickle the outbound group session, encrypting it with the given key.
    pub(crate) fn pickle(&mut self, pickle_key: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session and the output buffer is
        // `olm_pickle_outbound_group_session_length()` bytes long.
        unsafe {
            let length = olm_sys::olm_pickle_outbound_group_session_length(self.ptr);
            let mut pickle = vec![0u8; length];

            check(
                olm_sys::olm_pickle_outbound_group_session(
                    self.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to pickle the group session",
            );

            pickle
        }
    }

    /// The session key the current ratchet state can be shared with.
    pub(crate) fn session_key(&mut self) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session and the output buffer is
        // `olm_outbound_group_session_key_length()` bytes long.
        unsafe {
            let length = olm_sys::olm_outbound_group_session_key_length(self.ptr);
            let mut key = vec![0u8; length];

            check(
                olm_sys::olm_outbound_group_session_key(self.ptr, key.as_mut_ptr(), length),
                "libolm should be able to export the session key",
            );

            key
        }
    }

    /// Encrypt a message.
    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session, the plaintext is valid
        // for the length we pass along with it and the message buffer is as
        // long as libolm asked for.
        unsafe {
            let length = olm_sys::olm_group_encrypt_message_length(self.ptr, plaintext.len());
            let mut message = vec![0u8; length];

            check(
                olm_sys::olm_group_encrypt(
                    self.ptr,
                    plaintext.as_ptr(),
                    plaintext.len(),
                    message.as_mut_ptr(),
                    length,
                ),
                "libolm should be able to encrypt a message",
            );

            message
        }
    }
}

impl Drop for GroupSession {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is an initialised session that isn't used again.
        unsafe {
            olm_sys::olm_clear_outbound_group_session(self.ptr);
        }
    }
}

/// A libolm `OlmInboundGroupSession`.
pub(crate) struct InboundGroupSession {
    // The pointer below points into this buffer, so it must not be resized.
    _buffer: Box<[u8]>,
    ptr: *mut olm_sys::OlmInboundGroupSession,
}

impl InboundGroupSession {
    /// Allocate the memory libolm wants for an inbound group session and
    /// initialise it.
    fn allocate() -> Self {
        // SAFETY: `olm_inbound_group_session_size()` takes no arguments, and
        // `olm_inbound_group_session()` initialises a session in the buffer we
        // hand it, which is at least `olm_inbound_group_session_size()` bytes
        // long and outlives the session.
        unsafe {
            let mut buffer =
                vec![0u8; olm_sys::olm_inbound_group_session_size()].into_boxed_slice();
            let ptr = olm_sys::olm_inbound_group_session(buffer.as_mut_ptr().cast());

            Self { _buffer: buffer, ptr }
        }
    }

    /// Create an inbound group session from a session key.
    pub(crate) fn new(session_key: &[u8]) -> Self {
        let session = Self::allocate();

        // SAFETY: `session.ptr` is an initialised session and the session key
        // is valid for the length we pass along with it.
        unsafe {
            check(
                olm_sys::olm_init_inbound_group_session(
                    session.ptr,
                    session_key.as_ptr(),
                    session_key.len(),
                ),
                "libolm should be able to import the session key",
            );
        }

        session
    }

    /// Pickle the inbound group session, encrypting it with the given key.
    pub(crate) fn pickle(&mut self, pickle_key: &[u8]) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session and the output buffer is
        // `olm_pickle_inbound_group_session_length()` bytes long.
        unsafe {
            let length = olm_sys::olm_pickle_inbound_group_session_length(self.ptr);
            let mut pickle = vec![0u8; length];

            check(
                olm_sys::olm_pickle_inbound_group_session(
                    self.ptr,
                    pickle_key.as_ptr().cast(),
                    pickle_key.len(),
                    pickle.as_mut_ptr().cast(),
                    length,
                ),
                "libolm should be able to pickle the group session",
            );

            pickle
        }
    }

    /// Decrypt a message.
    ///
    /// The message is consumed since libolm destroys the input buffer. It gets
    /// copied once because the length of the plaintext has to be queried
    /// first, which destroys the buffer as well.
    pub(crate) fn decrypt(&mut self, mut message: Vec<u8>) -> Vec<u8> {
        // SAFETY: `self.ptr` is an initialised session, both message buffers
        // are valid for the lengths we pass along with them and the plaintext
        // buffer is as long as libolm asked for.
        unsafe {
            let mut message_for_length = message.clone();

            let length = check(
                olm_sys::olm_group_decrypt_max_plaintext_length(
                    self.ptr,
                    message_for_length.as_mut_ptr(),
                    message_for_length.len(),
                ),
                "libolm should be able to tell us the plaintext length",
            );

            let mut plaintext = vec![0u8; length];
            let mut message_index = 0u32;

            let length = check(
                olm_sys::olm_group_decrypt(
                    self.ptr,
                    message.as_mut_ptr(),
                    message.len(),
                    plaintext.as_mut_ptr(),
                    length,
                    &mut message_index,
                ),
                "libolm should be able to decrypt the message",
            );

            plaintext.truncate(length);

            plaintext
        }
    }
}

impl Drop for InboundGroupSession {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is an initialised session that isn't used again.
        unsafe {
            olm_sys::olm_clear_inbound_group_session(self.ptr);
        }
    }
}
