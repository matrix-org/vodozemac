// Copyright 2022 The Matrix.org Foundation C.I.C.
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

//! ⚠️ Low-level "hazmat" functions.
//!
//! This module contains low level APIs that should *not* be used or needed by
//! most users.
//!
//! These functions are exported to aid very advanced use cases.

#![cfg(feature = "low-level-api")]

pub mod olm;

pub use crate::cipher::{Cipher, Mac};
