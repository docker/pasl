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
use crate::authenticators::ApplicationName;
use crate::providers::Provide;
use interface::operations::Convert;
use interface::operations::{NativeOperation, NativeResult};
use interface::requests::{request::RequestHeader, Request, Response, ResponseStatus, Result};
use interface::requests::{BodyType, ProviderID};

/// Component responsible for unmarshalling requests, passing the operation
/// to the provider and marshalling the result.
///
/// It also provides assessment capabilities, letting the dispatcher know if
/// it can process a request.
pub struct BackEndHandler {
    // Send and Sync are required for Arc<FrontEndHandler> to be Send.
    provider: Box<dyn Provide + Send + Sync>,
    converter: Box<dyn Convert + Send + Sync>,
    provider_id: ProviderID,
    content_type: BodyType,
    accept_type: BodyType,
    version_min: u8,
    version_maj: u8,
}

impl BackEndHandler {
    /// Convert a request into a response, given the result of the operation.
    fn result_to_response(&self, result: NativeResult, request_hdr: RequestHeader) -> Response {
        let mut response = Response::from_request_header(request_hdr, ResponseStatus::Success);
        match self.converter.result_to_body(result) {
            Ok(body) => response.body = body,
            Err(status) => response.header.status = status,
        };
        response
    }

    /// Assess whether the backend handler-provider pair is capable of handling
    /// the request.
    ///
    /// # Errors
    /// - if the provider ID does not match, returns `ResponseStatus::WrongProviderID`
    /// - if the content type does not match, returns `ResponseStatus::ContentTypeNotSupported`
    /// - if the accept type does not match, returns `ResponseStatus::AcceptTypeNotSupported`
    /// - if the version is not supported, returns `ResponseStatus::VersionTooBig`
    pub fn is_capable(&self, request: &Request) -> Result<()> {
        let header = &request.header;

        // TODO: Add opcode checking here; store supported opcodes as a hashset
        //      - should we move header field parsing at deserialization?
        // TODO: if these two don't match the service should probably panic,
        // but I think it's reasonable to assume they do match
        if header.provider != self.provider_id {
            Err(ResponseStatus::WrongProviderID)
        } else if header.content_type != self.content_type {
            Err(ResponseStatus::ContentTypeNotSupported)
        } else if header.accept_type != self.accept_type {
            Err(ResponseStatus::AcceptTypeNotSupported)
        } else if (header.version_maj > self.version_maj)
            // TODO: This is incompatible with semantic versioning - does it hold?
            || (header.version_maj == self.version_maj && header.version_min > self.version_min)
        {
            Err(ResponseStatus::VersionTooBig)
        } else {
            Ok(())
        }
    }

    /// Unmarshall the request body, pass the operation to the provider and marshall
    /// the result back.
    ///
    /// If any of the steps fails, a response containing an appropriate status code is
    /// returned.
    pub fn execute_request(&self, request: Request, app_name: ApplicationName) -> Response {
        let opcode = request.header.opcode;
        let header = request.header;

        macro_rules! unwrap_or_else_return {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(status) => return Response::from_request_header(header, status),
                }
            };
        }

        match unwrap_or_else_return!(self.converter.body_to_operation(request.body, opcode)) {
            NativeOperation::Ping(op_ping) => {
                let result = unwrap_or_else_return!(self.provider.ping(op_ping));
                self.result_to_response(NativeResult::Ping(result), header)
            }
            NativeOperation::CreateKey(op_create_key) => {
                let result =
                    unwrap_or_else_return!(self.provider.create_key(app_name, op_create_key));
                self.result_to_response(NativeResult::CreateKey(result), header)
            }
            NativeOperation::ImportKey(op_import_key) => {
                let result =
                    unwrap_or_else_return!(self.provider.import_key(app_name, op_import_key));
                self.result_to_response(NativeResult::ImportKey(result), header)
            }
            NativeOperation::ExportPublicKey(op_export_public_key) => {
                let result = unwrap_or_else_return!(self
                    .provider
                    .export_public_key(app_name, op_export_public_key));
                self.result_to_response(NativeResult::ExportPublicKey(result), header)
            }
            NativeOperation::DestroyKey(op_destroy_key) => {
                let result =
                    unwrap_or_else_return!(self.provider.destroy_key(app_name, op_destroy_key));
                self.result_to_response(NativeResult::DestroyKey(result), header)
            }
            NativeOperation::AsymSign(op_asym_sign) => {
                let result =
                    unwrap_or_else_return!(self.provider.asym_sign(app_name, op_asym_sign));
                self.result_to_response(NativeResult::AsymSign(result), header)
            }
            NativeOperation::AsymVerify(op_asym_verify) => {
                let result =
                    unwrap_or_else_return!(self.provider.asym_verify(app_name, op_asym_verify));
                self.result_to_response(NativeResult::AsymVerify(result), header)
            }
        }
    }
}

#[derive(Default)]
pub struct BackEndHandlerBuilder {
    provider: Option<Box<dyn Provide + Send + Sync>>,
    converter: Option<Box<dyn Convert + Send + Sync>>,
    provider_id: Option<ProviderID>,
    content_type: Option<BodyType>,
    accept_type: Option<BodyType>,
    version_min: Option<u8>,
    version_maj: Option<u8>,
}

impl BackEndHandlerBuilder {
    pub fn new() -> BackEndHandlerBuilder {
        BackEndHandlerBuilder {
            provider: None,
            converter: None,
            provider_id: None,
            content_type: None,
            accept_type: None,
            version_min: None,
            version_maj: None,
        }
    }

    pub fn with_provider(mut self, provider: Box<dyn Provide + Send + Sync>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn with_converter(mut self, converter: Box<dyn Convert + Send + Sync>) -> Self {
        self.converter = Some(converter);
        self
    }

    pub fn with_provider_id(mut self, provider_id: ProviderID) -> Self {
        self.provider_id = Some(provider_id);
        self
    }

    pub fn with_content_type(mut self, content_type: BodyType) -> Self {
        self.content_type = Some(content_type);
        self
    }

    pub fn with_accept_type(mut self, accept_type: BodyType) -> Self {
        self.accept_type = Some(accept_type);
        self
    }

    pub fn with_version(mut self, version_min: u8, version_maj: u8) -> Self {
        self.version_maj = Some(version_maj);
        self.version_min = Some(version_min);
        self
    }

    pub fn build(self) -> BackEndHandler {
        BackEndHandler {
            provider: self.provider.expect("Provider missing"),
            converter: self.converter.expect("Converter missing"),
            provider_id: self.provider_id.expect("Provider ID missing"),
            content_type: self.content_type.expect("Content type missing"),
            accept_type: self.accept_type.expect("Accept type missing"),
            version_min: self.version_min.expect("Version min missing"),
            version_maj: self.version_maj.expect("Version maj missing"),
        }
    }
}
