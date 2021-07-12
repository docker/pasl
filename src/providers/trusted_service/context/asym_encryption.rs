// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::ts_protobuf::{
    AsymmetricDecryptIn, AsymmetricDecryptOut, AsymmetricEncryptIn, AsymmetricEncryptOut,
};
use super::Context;
use parsec_interface::operations::psa_algorithm::AsymmetricEncryption;
use parsec_interface::requests::ResponseStatus;
use std::convert::TryInto;
use zeroize::Zeroize;

impl Context {
    pub fn asym_encrypt(
        &self,
        key_id: u32,
        alg: AsymmetricEncryption,
        mut plaintext: Vec<u8>,
        mut salt: Vec<u8>,
    ) -> Result<Vec<u8>, ResponseStatus> {
        let alg = alg.try_into().map_err(|e| {
            plaintext.zeroize();
            salt.zeroize();
            e
        })?;
        let req = AsymmetricEncryptIn {
            id: key_id,
            alg,
            plaintext,
            salt,
        };
        let AsymmetricEncryptOut { ciphertext } = self.send_request(&req)?;

        Ok(ciphertext)
    }

    pub fn asym_decrypt(
        &self,
        key_id: u32,
        alg: AsymmetricEncryption,
        mut ciphertext: Vec<u8>,
        mut salt: Vec<u8>,
    ) -> Result<Vec<u8>, ResponseStatus> {
        let alg = alg.try_into().map_err(|e| {
            ciphertext.zeroize();
            salt.zeroize();
            e
        })?;
        let req = AsymmetricDecryptIn {
            id: key_id,
            alg,
            ciphertext,
            salt,
        };
        let AsymmetricDecryptOut { plaintext } = self.send_request(&req)?;

        Ok(plaintext)
    }
}
