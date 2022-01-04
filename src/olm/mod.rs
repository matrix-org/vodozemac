// Copyright 2021 The Matrix.org Foundation C.I.C.
// Copyright 2021 Damir Jelić, Denis Kasak
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

//! An implementation of the Olm ratchet.

mod account;
pub(crate) mod messages;
mod session;
mod session_keys;
mod shared_secret;

pub use account::{Account, AccountPickledJSON, InboundCreationResult};
pub use messages::OlmMessage;
pub use session::{DecryptionError, Session, SessionPickledJSON};
