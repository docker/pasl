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
use super::ResponseStatus;
use super::{Opcode, MAGIC_NUMBER};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Read, Result, Write};

const RESPONSE_HDR_SIZE: u16 = 20;

/// A primitive-based representation of the response header, following the wire format.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// private.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ResponseHeader {
    #[serde(skip_deserializing)]
    magic_number: u32,
    #[serde(skip_deserializing)]
    hdr_size: u16,
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: u8,
    pub session: u64,
    pub content_type: u8,
    body_len: u32,
    pub opcode: u16,
    pub status: u16,
}

impl ResponseHeader {
    /// Serialise the response header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, an error of kind `ErrorKind::InvalidData`
    /// is returned
    /// - if writing the header bytes fails, the resulting `std::io::Error` is
    /// propagated through
    fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        let hdr_bytes = match bincode::serialize(&self) {
            Ok(bytes) => bytes,
            Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        };

        stream.write_all(&hdr_bytes)?;

        Ok(())
    }

    /// Deserialise a response header from the given stream.
    ///
    /// # Errors
    /// - if either the magic number or the header size are invalid values,
    /// an error of kind `ErrorKind::InvalidData` is returned
    /// - if reading the fields after magic number and header size fails,
    /// the resulting `std::io::Error` is propagated through
    ///     - the read may fail due to a timeout if not enough bytes are
    ///     sent across
    /// - if the parsed bytes cannot be unmarshalled into the contained fields,
    /// an error of kind `ErrorKind::InvalidData` is returned
    fn read_from_stream(mut stream: &mut impl Read) -> Result<ResponseHeader> {
        let magic_number = get_from_stream!(stream, u32);
        let hdr_size = get_from_stream!(stream, u16);
        if magic_number != MAGIC_NUMBER || hdr_size != RESPONSE_HDR_SIZE {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let mut bytes = vec![0u8; hdr_size as usize];
        stream.read_exact(&mut bytes)?;

        let mut hdr: ResponseHeader = match bincode::deserialize(&bytes) {
            Ok(hdr) => hdr,
            Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        };
        hdr.magic_number = magic_number;
        hdr.hdr_size = hdr_size;

        Ok(hdr)
    }

    /// Create a new response header with default field values.
    pub fn new() -> ResponseHeader {
        ResponseHeader {
            magic_number: MAGIC_NUMBER,
            hdr_size: RESPONSE_HDR_SIZE,
            version_maj: 0,
            version_min: 0,
            provider: 0,
            session: 0,
            content_type: 0,
            body_len: 0,
            opcode: 0,
            status: 0,
        }
    }

    pub fn status(&self) -> ResponseStatus {
        let status_val = self.status;
        match ::num::FromPrimitive::from_u16(status_val) {
            Some(status) => status,
            None => panic!(
                "Value {} can not be represented as a ResponseStatus enum value.",
                status_val
            ),
        }
    }

    pub fn opcode(&self) -> Opcode {
        let opcode_val = self.opcode;
        match ::num::FromPrimitive::from_u16(opcode_val) {
            Some(opcode) => opcode,
            None => panic!(
                "Value {} can not be represented as an Opcode enum value.",
                opcode_val
            ),
        }
    }
}

/// Wrapper around the body of a response.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ResponseBody {
    bytes: Vec<u8>,
}

impl ResponseBody {
    fn new() -> ResponseBody {
        ResponseBody { bytes: Vec::new() }
    }

    fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<ResponseBody> {
        let bytes = get_from_stream!(stream; len);
        Ok(ResponseBody { bytes })
    }

    fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)
    }

    /// Create a `ResponseBody` from a vector of bytes.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> ResponseBody {
        ResponseBody { bytes }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of the body.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Representation of the response wire format.
///
/// Response body consists of an opaque vector of bytes with a length determined by
/// the `body_len` field in the header. Interpretation of said bytes is deferred to
/// the a converter which can handle the `content_type` defined in the header. Access
/// to the body is restricted to the `get_body` and `set_body` methods.
///
/// Serialisation and deserialisation are handled by `serde`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Response {
    pub header: ResponseHeader,
    body: ResponseBody,
}

impl Response {
    /// Create a response with default header and empty body.
    pub fn new() -> Response {
        Response {
            header: ResponseHeader::new(),
            body: ResponseBody::new(),
        }
    }

    /// Serialise response and write it to given stream.
    ///
    /// # Errors
    /// - if writing any of the subfields (header or body) fails, then the
    /// resulting `std::io::Error` is returned
    pub fn write_to_stream(&self, mut stream: &mut impl Write) -> Result<()> {
        self.header.write_to_stream(&mut stream)?;
        self.body.write_to_stream(&mut stream)?;

        Ok(())
    }

    /// Deserialise response from given stream.
    ///
    /// # Errors
    /// - if writing any of the subfields (header or body) fails, then the
    /// resulting `std::io::Error` is returned
    pub fn read_from_stream(mut stream: &mut impl Read) -> Result<Response> {
        let header = ResponseHeader::read_from_stream(&mut stream)?;
        let body = ResponseBody::read_from_stream(&mut stream, header.body_len as usize)?;

        Ok(Response { header, body })
    }

    /// Getter for response body.
    pub fn body(&self) -> &ResponseBody {
        &self.body
    }

    /// Setter for response body. Any previous body is discarded.
    ///
    /// Also fills in the `body_len` field of the header.
    pub fn set_body(&mut self, body: ResponseBody) {
        self.header.body_len = body.len() as u32;
        self.body = body;
    }
}

impl Default for Response {
    fn default() -> Response {
        Response::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::test_utils;
    use super::*;

    #[test]
    fn response_to_stream() {
        let mut mock = test_utils::MockReadWrite { buffer: Vec::new() };
        let response = get_response();

        response
            .write_to_stream(&mut mock)
            .expect("Failed to write response");

        assert_eq!(mock.buffer, get_response_bytes());
    }

    #[test]
    fn stream_to_response() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_response_bytes(),
        };

        let response = Response::read_from_stream(&mut mock).expect("Failed to read response");

        assert_eq!(response, get_response());
    }

    #[test]
    #[should_panic(expected = "Failed to read response")]
    fn failed_read() {
        let mut fail_mock = test_utils::MockFailReadWrite;

        Response::read_from_stream(&mut fail_mock).expect("Failed to read response");
    }

    #[test]
    #[should_panic(expected = "Failed to write response")]
    fn failed_write() {
        let response: Response = get_response();
        let mut fail_mock = test_utils::MockFailReadWrite;

        response
            .write_to_stream(&mut fail_mock)
            .expect("Failed to write response");
    }

    fn get_response() -> Response {
        let body = ResponseBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let header = ResponseHeader {
            magic_number: 0x5EC0_A710,
            hdr_size: 0x00_14,
            version_maj: 0xde,
            version_min: 0xf0,
            provider: 0x00,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: 0x99,
            body_len: 0x00_00_00_03,
            opcode: 0xbb_cc,
            status: 0xdd_ee,
        };
        Response { header, body }
    }

    fn get_response_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x14, 0x00, 0xde, 0xf0, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x99, 0x03, 0x00, 0x00, 0x00, 0xcc, 0xbb, 0xee, 0xdd, 0x70, 0x80,
            0x90,
        ]
    }

}
