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
use crate::authenticators::Authenticate;
use crate::back::dispatcher::Dispatcher;
use interface::requests::AuthType;
use interface::requests::ResponseStatus;
use interface::requests::{Request, Response};
use std::collections::HashMap;
use std::io::{Read, Write};

/// Service component that serializes requests and deserializes responses
/// from/to the stream provided by the listener.
///
/// Requests are passed forward to the `Dispatcher`.
pub struct FrontEndHandler {
    dispatcher: Dispatcher,
    // Send and Sync are required for Arc<FrontEndHandler> to be Send.
    authenticators: HashMap<AuthType, Box<dyn Authenticate + Send + Sync>>,
}

impl FrontEndHandler {
    /// Handle new connections on the underlying IPC mechanism.
    ///
    /// Unmarshalls a request from the stream, passes it to the dispatcher and marshalls
    /// the response back onto the stream.
    ///
    /// If an error occurs during (un)marshalling, no operation will be performed and the
    /// method will return.
    pub fn handle_request<T: Read + Write>(&self, mut stream: T) {
        // Read bytes from stream
        // De-Serialise bytes into a request
        let request = match Request::read_from_stream(&mut stream) {
            Ok(request) => request,
            Err(status) => {
                println!("Failed to read request; status: {}", status);

                let response = Response::from_status(status);
                if let Err(status) = response.write_to_stream(&mut stream) {
                    println!("Failed to write response; status: {}", status);
                }
                return;
            }
        };
        // Find an authenticator that is capable to authenticate the request
        let response =
            if let Some(authenticator) = self.authenticators.get(&request.header.auth_type) {
                // Authenticate the request
                match authenticator.authenticate(&request.auth) {
                    // Send the request to the dispatcher
                    // Get a response back
                    Ok(app_name) => self.dispatcher.dispatch_request(request, app_name),
                    Err(status) => Response::from_request_header(request.header, status),
                }
            } else {
                Response::from_request_header(
                    request.header,
                    ResponseStatus::AuthenticatorNotRegistered,
                )
            };

        // Serialise the responso into bytes
        // Write bytes to stream
        match response.write_to_stream(&mut stream) {
            Ok(_) => println!("Request handled successfully"),
            Err(err) => println!("Failed to send response; error: {}", err),
        }
    }
}

#[derive(Default)]
pub struct FrontEndHandlerBuilder {
    dispatcher: Option<Dispatcher>,
    authenticators: Option<HashMap<AuthType, Box<dyn Authenticate + Send + Sync>>>,
}

impl FrontEndHandlerBuilder {
    pub fn new() -> Self {
        FrontEndHandlerBuilder {
            dispatcher: None,
            authenticators: None,
        }
    }

    pub fn with_dispatcher(mut self, dispatcher: Dispatcher) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    pub fn with_authenticator(
        mut self,
        auth_type: AuthType,
        authenticator: Box<dyn Authenticate + Send + Sync>,
    ) -> Self {
        match &mut self.authenticators {
            Some(authenticators) => {
                authenticators.insert(auth_type, authenticator);
            }
            None => {
                let mut map = HashMap::new();
                map.insert(auth_type, authenticator);
                self.authenticators = Some(map);
            }
        };

        self
    }

    pub fn build(self) -> FrontEndHandler {
        FrontEndHandler {
            dispatcher: self.dispatcher.expect("Dispatcher missing"),
            authenticators: self.authenticators.expect("Authenticators missing"),
        }
    }
}
