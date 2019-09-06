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
use num_derive::FromPrimitive;

pub mod utils;
pub mod request;
pub mod response;

const MAGIC_NUMBER: u32 = 0x5EC0_A710;

/// Listing of provider types and their associated codes.
///
/// Passed in headers as `provider`.
#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum ProviderID {
    CoreProvider = 0,
}

/// Listing of body encoding types and their associated codes.
///
/// Passed in headers as `content_type` and `accept_type`.
#[derive(FromPrimitive, Copy, Clone)]
pub enum BodyType {
    Protobuf = 0,
}

/// Listing of available operations and their associated opcode.
///
/// Passed in headers as `opcode`.
#[derive(FromPrimitive, Copy, Clone)]
pub enum Opcode {
    Ping = 0,
}

#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum AuthType {
    Simple = 0,
}