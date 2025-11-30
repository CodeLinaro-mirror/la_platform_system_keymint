// Copyright 2025, The Android Open Source Project
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

//! This module handles the generation of timestamp tokens.

use super::KeyMintTa;
use alloc::vec;
use alloc::vec::Vec;
use kmr_common::{km_err, Error};

impl KeyMintTa {
    pub(crate) fn generate_timestamp_token(&self, encoded_req: &[u8]) -> Result<Vec<u8>, Error> {
        // Non-secure TA implementation:
        if encoded_req.is_empty() {
            return Err(km_err!(InvalidArgument, "encoded_req cannot be empty"));
        }
        // Dummy ASN.1 SEQUENCE
        // TODO(b/455591722): implement!
        Ok(vec![0x30, 0x01, 0x00])
    }
}
