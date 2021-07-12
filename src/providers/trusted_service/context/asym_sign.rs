// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::error::Error;
use super::ts_protobuf::{SignHashIn, SignHashOut, VerifyHashIn};
use super::Context;
use log::info;
use psa_crypto::types::algorithm::AsymmetricSignature;
use std::convert::TryInto;

impl Context {
    /// Sign a hash with an asymmetric key given its ID and the signing algorithm.
    pub fn sign_hash(
        &self,
        key_id: u32,
        hash: Vec<u8>,
        algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>, Error> {
        info!("Handling SignHash request");
        let proto_req = SignHashIn {
            id: key_id,
            hash,
            alg: algorithm.try_into()?,
        };
        let SignHashOut { signature } = self.send_request(&proto_req)?;

        Ok(signature)
    }

    /// Verify a signature on a hash with an asymmetric key given its ID and the signing algorithm.
    pub fn verify_hash(
        &self,
        key_id: u32,
        hash: Vec<u8>,
        signature: Vec<u8>,
        algorithm: AsymmetricSignature,
    ) -> Result<(), Error> {
        info!("Handling VerifyHash request");
        let proto_req = VerifyHashIn {
            id: key_id,
            hash,
            signature,
            alg: algorithm.try_into()?,
        };
        self.send_request(&proto_req)?;

        Ok(())
    }
}
