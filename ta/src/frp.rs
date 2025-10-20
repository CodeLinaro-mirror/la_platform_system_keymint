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

//! Functionality for factory reset protection.

use crate::{
    device::{FrpDataStorage, FrpSecretStorage},
    Error, KeyMintTa,
};
use alloc::vec::Vec;
use kmr_common::frp_err;

impl KeyMintTa {
    pub(crate) fn frp_active(&self) -> bool {
        self.frp_active
    }

    pub(crate) fn activate_frp(&mut self) -> Result<(), Error> {
        let _ = self.frp_secret_storage()?;
        self.frp_active = true;
        Ok(())
    }

    pub(crate) fn deactivate_frp(&mut self, candidate_secret: [u8; 32]) -> Result<bool, Error> {
        let stored_secret = self.frp_secret_storage()?.retrieve_secret()?;
        if self.imp.compare.eq(&candidate_secret, &stored_secret) {
            self.frp_active = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn set_frp_secret(&mut self, new_secret: [u8; 32]) -> Result<(), Error> {
        if self.frp_active {
            return Err(frp_err!(FrpIsActive, "FRP is active"));
        }
        self.frp_secret_storage_mut()?.store_secret(new_secret)?;
        Ok(())
    }

    pub(crate) fn get_frp_secret(&self) -> Result<[u8; 32], Error> {
        if self.frp_active {
            return Err(frp_err!(FrpIsActive, "FRP is active"));
        }
        self.frp_secret_storage()?.retrieve_secret()
    }

    pub(crate) fn store_frp_data(&mut self, key: &str, data: &[u8]) -> Result<(), Error> {
        self.frp_data_storage_mut()?.store_data(key, data)
    }

    pub(crate) fn retrieve_frp_data(&self, key: &str) -> Result<Vec<u8>, Error> {
        match self.frp_data_storage()?.retrieve_data(key) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(frp_err!(IllegalArgument, "Key {key} not found")),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn delete_frp_data(&mut self, key: &str) -> Result<(), Error> {
        self.frp_data_storage_mut()?.delete_data(key)
    }

    pub(crate) fn delete_all_frp_data(&mut self) -> Result<(), Error> {
        self.frp_data_storage_mut()?.clear()
    }

    pub(crate) fn frp_secret_storage(&self) -> Result<&dyn FrpSecretStorage, Error> {
        match &self.dev.frp_secret_storage {
            Some(frp_secret_storage) => Ok(frp_secret_storage.as_ref()),
            _ => Err(frp_err!(Unsupported, "FRP secret storage not implemented")),
        }
    }

    pub(crate) fn frp_data_storage(&self) -> Result<&dyn FrpDataStorage, Error> {
        match &self.dev.frp_data_storage {
            Some(storage) => Ok(storage.as_ref()),
            _ => Err(frp_err!(Unsupported, "FRP data storage not implemented")),
        }
    }

    pub(crate) fn frp_secret_storage_mut(&mut self) -> Result<&mut dyn FrpSecretStorage, Error> {
        match &mut self.dev.frp_secret_storage {
            Some(frp_secret_storage) => Ok(frp_secret_storage.as_mut()),
            _ => Err(frp_err!(Unsupported, "FRP secret storage not implemented")),
        }
    }

    pub(crate) fn frp_data_storage_mut(&mut self) -> Result<&mut dyn FrpDataStorage, Error> {
        match &mut self.dev.frp_data_storage {
            Some(storage) => Ok(storage.as_mut()),
            _ => Err(frp_err!(Unsupported, "FRP data storage not implemented")),
        }
    }
}
