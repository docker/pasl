// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
mod ping;

use crate::requests::{
    request::RequestBody,
    response::{ResponseBody, ResponseStatus},
    Opcode,
};
pub use ping::{OpPing, ResultPing};

/// Container type for operation conversion values, holding a native operation object
/// to be passed in/out of a converter.
pub enum ConvertOperation {
    Ping(ping::OpPing),
}

/// Container type for result conversion values, holding a native result object to be
/// passed in/out of the converter.
pub enum ConvertResult {
    Ping(ping::ResultPing),
}

/// Definition of the operations converters must implement to allow usage of a specific
/// `BodyType`.
pub trait Convert {
    /// Create a native operation object from a request body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_operation(
        &self,
        body: &RequestBody,
        opcode: Opcode,
    ) -> Result<ConvertOperation, ResponseStatus>;

    /// Create a request body from a native operation object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn body_from_operation(
        &self,
        operation: ConvertOperation,
    ) -> Result<RequestBody, ResponseStatus>;

    /// Create a native result object from a response body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_result(
        &self,
        body: &ResponseBody,
        opcode: Opcode,
    ) -> Result<ConvertResult, ResponseStatus>;

    /// Create a response body from a native result object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn body_from_result(&self, result: ConvertResult) -> Result<ResponseBody, ResponseStatus>;
}