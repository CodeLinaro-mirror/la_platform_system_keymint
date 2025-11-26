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

//! `ITimeStamper` HAL device implementation.

use super::{ChannelHalService, SerializedChannel};
use crate::binder::{self, BinderFeatures, Interface, SpIBinder};
use crate::hal::timestamp::ITimeStamper::{BnTimeStamper, ITimeStamper};
use crate::hal::timestamp::TimeStampReq::TimeStampReq;
use kmr_wire::{TimeStampGenerateRequest, TimeStampGenerateResponse};
use std::sync::{Arc, Mutex, MutexGuard};

/// Rust implementation of the `ITimeStamper` HAL.
#[derive(Debug)]
pub struct Device<T: SerializedChannel> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + Send + 'static> Device<T> {
    /// Create a new instance.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }

    /// Create a new binder instance.
    pub fn new_as_binder(channel: Arc<Mutex<T>>) -> SpIBinder {
        let service = Self::new(channel);
        BnTimeStamper::new_binder(service, BinderFeatures::default()).as_binder()
    }
}

impl<T: SerializedChannel + Send + 'static> Interface for Device<T> {}

impl<T: SerializedChannel> ChannelHalService<T> for Device<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }
}

impl<T: SerializedChannel + Send + 'static> ITimeStamper for Device<T> {
    fn createRfc3161TimestampToken(&self, timestamp_req: &TimeStampReq) -> binder::Result<Vec<u8>> {
        let request = TimeStampGenerateRequest { encoded_req: timestamp_req.encodedReq.clone() };
        let response: TimeStampGenerateResponse = self.execute(request)?;
        Ok(response.timestamp_token)
    }
}
