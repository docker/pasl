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
mod convert_ping;
mod convert_create_key;
mod convert_key_attributes;

#[rustfmt::skip]
mod generated_ops;

use crate::operations::{Convert, ConvertOperation, ConvertResult};
use crate::requests::{
    request::RequestBody,
    response::{ResponseBody, ResponseStatus},
    Opcode,
};
use generated_ops::create_key::{OpCreateKeyProto, ResultCreateKeyProto};
use generated_ops::ping::{OpPingProto, ResultPingProto};
use prost::Message;
use std::convert::TryInto;

macro_rules! wire_to_native {
    ($body:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = Default::default();
        if proto.merge($body).is_err() {
            return Err(ResponseStatus::DeserializingBodyFailed);
        }
        proto.try_into()?
    }};
}

macro_rules! native_to_wire {
    ($native_msg:expr, $proto_type:ty) => {{
        let proto: $proto_type = $native_msg.try_into()?;
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_to_operation(
        &self,
        body: &RequestBody,
        opcode: Opcode,
    ) -> Result<ConvertOperation, ResponseStatus> {
        match opcode {
            Opcode::Ping => Ok(ConvertOperation::Ping(wire_to_native!(
                body.bytes(),
                OpPingProto
            ))),
            Opcode::CreateKey => Ok(ConvertOperation::CreateKey(wire_to_native!(
                body.bytes(),
                OpCreateKeyProto
            ))),
        }
    }

    fn body_from_operation(
        &self,
        operation: ConvertOperation,
    ) -> Result<RequestBody, ResponseStatus> {
        match operation {
            ConvertOperation::Ping(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpPingProto
            ))),
            ConvertOperation::CreateKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpCreateKeyProto
            ))),
        }
    }

    fn body_to_result(
        &self,
        body: &ResponseBody,
        opcode: Opcode,
    ) -> Result<ConvertResult, ResponseStatus> {
        match opcode {
            Opcode::Ping => Ok(ConvertResult::Ping(wire_to_native!(
                body.bytes(),
                ResultPingProto
            ))),
            Opcode::CreateKey => Ok(ConvertResult::CreateKey(wire_to_native!(
                body.bytes(),
                ResultCreateKeyProto
            ))),
        }
    }

    fn body_from_result(&self, result: ConvertResult) -> Result<ResponseBody, ResponseStatus> {
        match result {
            ConvertResult::Ping(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultPingProto
            ))),
            ConvertResult::CreateKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultCreateKeyProto
            ))),
        }
    }
}
