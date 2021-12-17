// Copyright 2020 Johannes Hayeß
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This is a wrapper for [`libolm`](https://git.matrix.org/git/olm/about/).
//! It exposes all original functionality, split into task oriented modules.
//!
//! This wrapper takes care of memory allocation for you, so all functions
//! in the original library exposing the buffer length of certain read/write
//! buffers (and similar functionality) are not exposed by this wrapper.
//!
//! Random number generation is also handled internally and hence there are no
//! function arguments for supplying random data.
//!
//! String arguments will vary in ownership requirements when being provided as a
//! function argument. This is because `libolm` will sometimes mutate this data and
//! sometimes won't. To avoid breaking the ownership model, full ownership is required
//! for the former case.
//!
//! All errors of the type `NOT_ENOUGH_RANDOM` and `OUTPUT_BUFFER_TOO_SMALL` from
//! `libolm` that are encountered result in a panic, as they are unrecoverably fatal.
//! Similarly the output from `libolm` is assumed to be trusted, except for encryption
//! functions. If the string output from any other function is not properly encoded
//! as UTF-8, a panic will occur as well.
//! In case a function can panic, it is annotated as such in the documentation.
//!
//! All panics can be considered unreachable, they are documented however for the
//! purpose of transparency.

pub mod account;
pub mod errors;
pub mod inbound_group_session;
pub mod outbound_group_session;
pub mod pk;
pub mod sas;
pub mod session;
pub mod utility;

use std::alloc::{GlobalAlloc as _, Layout, System};
use std::fmt;
use std::os::raw::c_void;
use std::ptr;

use getrandom as random;
use zeroize::Zeroizing;

/// A [`mod@getrandom`] wrapper that panics if the call is unsuccessful.
///
/// # Arguments
///
/// * `buffer` - The buffer that should be filled with random data.
///
/// # Panics
///
/// Panics if the operating system can't provide enough random data.
pub(crate) fn getrandom(buffer: &mut Zeroizing<Vec<u8>>) {
    random::getrandom(buffer).expect(
        "Operating system didn't provide enough random data to securely generate the private keys.",
    );
}

/// Marking these as Send is safe because nothing will modify the pointer under
/// us from the C side. Sync on the other hand is unsafe since libolm doesn't do
/// any synchronization.
unsafe impl Send for account::OlmAccount {}
unsafe impl Send for session::OlmSession {}
unsafe impl Send for sas::OlmSas {}
unsafe impl Send for pk::OlmPkDecryption {}
unsafe impl Send for pk::OlmPkEncryption {}
unsafe impl Send for pk::OlmPkSigning {}
unsafe impl Send for inbound_group_session::OlmInboundGroupSession {}
unsafe impl Send for outbound_group_session::OlmOutboundGroupSession {}

/// Used for storing the version number of libolm.
/// Solely returned by [`get_library_version()`](fn.get_library_version.html).
#[derive(Debug, PartialEq)]
pub struct OlmVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

/// Used for setting the encryption parameter for pickling (serialisation) functions.
/// `Unencrypted` is functionally equivalent to `Encrypted{key: [].to_vec() }`, but is much more clear.
/// Pickling modes have to be equivalent for pickling and unpickling operations to succeed.
/// `Encrypted` takes ownership of `key`, in order to properly destroy it after use.
pub enum PicklingMode {
    Unencrypted,
    Encrypted { key: Vec<u8> },
}

/// Convenience function that maps `Unencrypted` to an empty key, or
/// unwraps `Encrypted`. Mostly for reducing code duplication.
pub(crate) fn convert_pickling_mode_to_key(mode: PicklingMode) -> Vec<u8> {
    match mode {
        PicklingMode::Unencrypted => Vec::new(),
        PicklingMode::Encrypted { key: x } => x,
    }
}

/// Returns the version number of the currently utilised `libolm`.
///
/// # C-API equivalent
/// `olm_get_library_version`
pub fn get_library_version() -> OlmVersion {
    let mut major = 0;
    let mut minor = 0;
    let mut patch = 0;
    let major_ptr: *mut u8 = &mut major;
    let minor_ptr: *mut u8 = &mut minor;
    let patch_ptr: *mut u8 = &mut patch;

    unsafe {
        olm_sys::olm_get_library_version(major_ptr, minor_ptr, patch_ptr);
    }

    OlmVersion {
        major,
        minor,
        patch,
    }
}

/// Helper type that just holds a one byte aligned allocation but doesn't allow
/// safe code to access its contents.
///
/// For use with the olm functions that take a buffer and return a typed pointer
/// into the same allocation after initializing it.
struct ByteBuf(*mut [u8]);

impl ByteBuf {
    fn new(size: usize) -> Self {
        assert!(size != 0);

        let layout = Layout::from_size_align(size, 1).unwrap();
        let data = unsafe { System.alloc(layout) };
        Self(ptr::slice_from_raw_parts_mut(data, size))
    }

    fn as_mut_void_ptr(&mut self) -> *mut c_void {
        self.0 as _
    }
}

impl fmt::Debug for ByteBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ByteBuf>")
    }
}

impl Drop for ByteBuf {
    fn drop(&mut self) {
        // Should ideally use the safe <*mut [T]>::len(), but that is unstable.
        // https://github.com/rust-lang/rust/issues/71146
        let size = unsafe { (*self.0).len() };
        let layout = Layout::from_size_align(size, 1).unwrap();

        // Should ideally use <*mut [T]>::as_mut_ptr(), but that is unstable.
        // https://github.com/rust-lang/rust/issues/74265
        let data = self.0 as *mut u8;

        unsafe {
            System.dealloc(data, layout);
        }
    }
}
