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

//! `IFactoryResetProtection` HAL device implementation.

use crate::{hal::frp::IFactoryResetProtection, ChannelHalService, SerializedChannel};
use binder::Result;
use kmr_wire::{
    FrpActivateRequest, FrpActivateResponse, FrpDeactivateRequest, FrpDeactivateResponse,
    FrpDeleteAllDataRequest, FrpDeleteAllDataResponse, FrpDeleteDataRequest, FrpDeleteDataResponse,
    FrpGetSecretRequest, FrpGetSecretResponse, FrpIsActiveRequest, FrpIsActiveResponse,
    FrpRetrieveDataRequest, FrpRetrieveDataResponse, FrpSetSecretRequest, FrpSetSecretResponse,
    FrpStoreDataRequest, FrpStoreDataResponse,
};
use std::sync::{Arc, Mutex, MutexGuard};

/// `IFactoryResetProtection` implementation which converts all method invocations to serialized
/// requests that are sent down the associated channel.
pub struct Device<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + Send> binder::Interface for Device<T> {}

impl<T: SerializedChannel + 'static> Device<T> {
    /// Construct a new instance that uses the provided channel.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }

    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder(
        channel: Arc<Mutex<T>>,
    ) -> binder::Strong<dyn IFactoryResetProtection::IFactoryResetProtection> {
        IFactoryResetProtection::BnFactoryResetProtection::new_binder(
            Self::new(channel),
            binder::BinderFeatures::default(),
        )
    }
}

impl<T: SerializedChannel> ChannelHalService<T> for Device<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }
}

impl<T: SerializedChannel> IFactoryResetProtection::IFactoryResetProtection for Device<T> {
    fn isActive(&self) -> Result<bool> {
        let rsp: FrpIsActiveResponse = self.execute(FrpIsActiveRequest {})?;
        Ok(rsp.is_active)
    }

    fn activate(&self) -> Result<()> {
        let _rsp: FrpActivateResponse = self.execute(FrpActivateRequest {})?;
        Ok(())
    }

    fn deactivate(&self, frp_secret: &[u8; 32]) -> Result<bool> {
        let rsp: FrpDeactivateResponse =
            self.execute(FrpDeactivateRequest { candidate_secret: *frp_secret })?;
        Ok(rsp.result)
    }

    fn setSecret(&self, frp_secret: &[u8; 32]) -> Result<()> {
        let _rsp: FrpSetSecretResponse =
            self.execute(FrpSetSecretRequest { new_secret: *frp_secret })?;
        Ok(())
    }

    fn getSecret(&self) -> Result<[u8; 32]> {
        let rsp: FrpGetSecretResponse = self.execute(FrpGetSecretRequest {})?;
        Ok(rsp.frp_secret)
    }

    fn storeData(&self, key: &str, data: &[u8]) -> Result<()> {
        let _rsp: FrpStoreDataResponse =
            self.execute(FrpStoreDataRequest { key: key.to_string(), data: data.to_vec() })?;
        Ok(())
    }

    fn retrieveData(&self, key: &str) -> Result<Vec<u8>> {
        let rsp: FrpRetrieveDataResponse =
            self.execute(FrpRetrieveDataRequest { key: key.to_string() })?;
        Ok(rsp.data)
    }

    fn deleteData(&self, key: &str) -> Result<()> {
        let _rsp: FrpDeleteDataResponse =
            self.execute(FrpDeleteDataRequest { key: key.to_string() })?;
        Ok(())
    }

    fn deleteAllData(&self) -> Result<()> {
        let _rsp: FrpDeleteAllDataResponse = self.execute(FrpDeleteAllDataRequest {})?;
        Ok(())
    }
}
