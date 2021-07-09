// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::error;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderId, ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use parsec_interface::secrecy::Secret;
use psa_crypto::types::key::PSA_KEY_ID_USER_MAX;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

/// Creates a new PSA Key ID
pub fn create_key_id(max_current_id: &AtomicU32) -> Result<u32> {
    // fetch_add adds 1 to the old value and returns the old value, so add 1 to local value for new ID
    let new_key_id = max_current_id.fetch_add(1, Relaxed) + 1;
    if new_key_id > PSA_KEY_ID_USER_MAX {
        // If storing key failed and no other keys were created in the mean time, it is safe to
        // decrement the key counter.
        let _ = max_current_id.store(PSA_KEY_ID_USER_MAX, Relaxed);
        error!("PSA max key ID limit of {} reached", PSA_KEY_ID_USER_MAX);
        return Err(ResponseStatus::PsaErrorInsufficientMemory);
    }

    Ok(new_key_id)
}

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, key_name);
        self.key_info_store.does_not_exist(&key_triple)?;

        let key_id = create_key_id(&self.id_counter)?;

        match self.context.generate_key(key_attributes, key_id) {
            Ok(_) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_triple, &key_id, key_attributes)
                {
                    if self.context.destroy_key(key_id).is_err() {
                        error!("Failed to destroy the previously generated key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Generate key error", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_data = op.data;
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, key_name);
        self.key_info_store.does_not_exist(&key_triple)?;

        let key_id = create_key_id(&self.id_counter)?;

        match self
            .context
            .import_key(key_attributes, key_id, key_data.expose_secret())
        {
            Ok(_) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_triple, &key_id, key_attributes)
                {
                    if self.context.destroy_key(key_id).is_err() {
                        error!("Failed to destroy the previously generated key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_import_key::Result {})
                }
            }
            Err(error) => {
                format_error!("Import key status: ", error);
                Err(error.into())
            }
        }
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        match self.context.export_public_key(key_id) {
            Ok(pub_key) => Ok(psa_export_public_key::Result {
                data: pub_key.into(),
            }),
            Err(error) => {
                format_error!("Export public key status: ", error);
                Err(error.into())
            }
        }
    }

    pub(super) fn psa_export_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        match self.context.export_key(key_id) {
            Ok(key) => Ok(psa_export_key::Result {
                data: Secret::new(key),
            }),
            Err(error) => {
                format_error!("Export key status: ", error);
                Err(error.into())
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let _ = self.key_info_store.remove_key_info(&key_triple)?;

        match self.context.destroy_key(key_id) {
            Ok(()) => Ok(psa_destroy_key::Result {}),
            Err(error) => {
                format_error!("Destroy key status: ", error);
                Err(error.into())
            }
        }
    }
}
