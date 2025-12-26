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

//! BoringSSL-based implementation of ML-DSA functionality.

use alloc::boxed::Box;
use alloc::vec::Vec;
use bssl_crypto::mldsa::{Prehash65, PrivateKey65};
use kmr_common::crypto::{self, mldsa::Key, AccumulatingOperation, MlDsa, OpaqueOr};
use kmr_common::{explicit, Error};

/// [`kmr_common::crypto::MlDsa`] implementation based on BoringSSL.
pub struct BoringMlDsa;

enum BoringPrivateKey {
    MlDsa65(PrivateKey65),
    // TODO(b/395069628): add 87 variant
    // MlDsa87(PrivateKey87),
}

impl From<&Key> for BoringPrivateKey {
    fn from(key: &Key) -> Self {
        match key {
            Key::MlDsa65(seed) => Self::MlDsa65(PrivateKey65::from_seed(seed)),
            Key::MlDsa87(_seed) => todo!("b/395069628: add MlDsa87(PrivateKey87)"),
        }
    }
}

impl MlDsa for BoringMlDsa {
    fn subject_public_key(&self, key: &OpaqueOr<Key>) -> Result<Vec<u8>, Error> {
        let key = explicit!(key)?;
        let bssl_key = BoringPrivateKey::from(key);
        Ok(match bssl_key {
            BoringPrivateKey::MlDsa65(k) => k.to_public_key().to_bytes(),
            // TODO(b/395069628): add 87 variant
            // BoringPrivateKey::MlDsa87(k) => k.to_public_key().to_bytes(),
        })
    }

    fn begin_sign(&self, key: OpaqueOr<Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let bssl_key = BoringPrivateKey::from(&key);
        let op = match bssl_key {
            BoringPrivateKey::MlDsa65(key) => {
                let prehash = key.to_public_key().prehash();
                BoringMlDsaSignOperation::MlDsa65(key, prehash)
            } // TODO(b/395069628): add 87 variant
              // BoringPrivateKey::MlDsa87(key) => {
              //     let prehash = key.to_public_key().prehash();
              //    BoringMlDsaSignOperation::MlDsa87(key, prehash)
              //}
        };
        Ok(Box::new(op))
    }
}

/// ML-DSA signing operation based on BoringSSL.
enum BoringMlDsaSignOperation {
    MlDsa65(PrivateKey65, Prehash65),
    // TODO(b/395069628): add 87 variant
    // MlDsa87(PrivateKey87, Prehash87),
}

impl crypto::AccumulatingOperation for BoringMlDsaSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        match self {
            Self::MlDsa65(_k, prehash) => prehash.update(data),
            // TODO(b/395069628): add 87 variant
            // Self::MlDsa87(_k, prehash) => prehash.update(data),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        Ok(match *self {
            Self::MlDsa65(key, prehash) => key.sign_prehashed(prehash),
            // TODO(b/395069628): add 87 variant
            // Self::MlDsa87(key, prehash) => key.sign_prehashed(prehash),
        })
    }
}
