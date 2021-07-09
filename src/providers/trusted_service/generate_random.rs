// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::psa_generate_random;
use parsec_interface::requests::Result;

impl Provider {
    pub(super) fn psa_generate_random_internal(
        &self,
        op: psa_generate_random::Operation,
    ) -> Result<psa_generate_random::Result> {
        let size = op.size;

        match self.context.generate_random(size) {
            Ok(random_bytes) => Ok(psa_generate_random::Result {
                random_bytes: random_bytes.into(),
            }),
            Err(error) => {
                format_error!("Generate random status: ", error);
                Err(error.into())
            }
        }
    }
}
