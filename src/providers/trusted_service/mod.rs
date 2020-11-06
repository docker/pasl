// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Trusted Service provider
//!
//! This provider is backed by a crypto Trusted Service deployed in TrustZone
use super::mbed_crypto::key_management as mbed_crypto_key_management;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use crate::key_info_managers::ManageKeyInfo;
use crate::providers::Provide;
use context::Context;
use derivative::Derivative;
use log::{error, trace};
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::{psa_destroy_key, psa_generate_key};
use parsec_interface::requests::{Opcode, ProviderID, Result};
use psa_crypto::types::key;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};
use uuid::Uuid;

mod context;
mod key_management;

const SUPPORTED_OPCODES: [Opcode; 2] = [Opcode::PsaDestroyKey, Opcode::PsaGenerateKey];

/// Trusted Service provider structure
///
/// Currently the provider only supports volatile keys due to limitations in the stack
/// underneath us. Therefore none of the key information is persisted, being kept instead
/// in a map for fast access.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    context: Context,
    // When calling write on a reference of key_info_store, a type
    // std::sync::RwLockWriteGuard<dyn ManageKeyInfo + Send + Sync> is returned. We need to use the
    // dereference operator (*) to access the inner type dyn ManageKeyInfo + Send + Sync and then
    // reference it to match with the method prototypes.
    #[derivative(Debug = "ignore")]
    key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,

    // Holds the highest ID of all keys (including destroyed keys). New keys will receive an ID of
    // id_counter + 1. Once id_counter reaches the highest allowed ID, no more keys can be created.
    id_counter: AtomicU32,
}

impl Provider {
    /// Creates and initialise a new instance of Provider.
    fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> anyhow::Result<Provider> {
        let ts_provider = Provider {
            key_info_store,
            context: Context::connect()?,
            id_counter: AtomicU32::new(key::PSA_KEY_ID_USER_MIN),
        };
        let mut max_key_id: key::psa_key_id_t = key::PSA_KEY_ID_USER_MIN;
        {
            // The local scope allows to drop store_handle and local_ids_handle in order to return
            // the ts_provider.
            let mut store_handle = ts_provider
                .key_info_store
                .write()
                .expect("Key store lock poisoned");
            let mut to_remove: Vec<KeyTriple> = Vec::new();
            // Go through all TrustedServiceProvider key triple to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match store_handle.get_all(ProviderID::TrustedService) {
                Ok(key_triples) => {
                    for key_triple in key_triples.iter().cloned() {
                        let key_id = match mbed_crypto_key_management::get_key_id(
                            &key_triple,
                            &*store_handle,
                        ) {
                            Ok(key_id) => key_id,
                            Err(response_status) => {
                                error!("Error getting the Key ID for triple:\n{}\n(error: {}), continuing...", key_triple, response_status);
                                to_remove.push(key_triple.clone());
                                continue;
                            }
                        };

                        if ts_provider.context.check_key_exists(key_id)? {
                            if key_id > max_key_id {
                                max_key_id = key_id;
                            }
                        } else {
                            to_remove.push(key_triple.clone());
                        }
                    }
                }
                Err(string) => {
                    error!("Key Info Manager error when obtaining handles: {}", string);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, string).into());
                }
            };
            for key_triple in to_remove.iter() {
                if let Err(string) = store_handle.remove(key_triple) {
                    error!("Key Info Manager error when removing handles: {}", string);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, string).into());
                }
            }
        }
        ts_provider.id_counter.store(max_key_id, Ordering::Relaxed);
        Ok(ts_provider)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        Ok((ProviderInfo {
            // Assigned UUID for this provider: 71129441-508a-4da6-b6e8-7b98a777e4c0
            uuid: Uuid::parse_str("71129441-508a-4da6-b6e8-7b98a777e4c0")?,
            description: String::from("Provider exposing functionality provided by the Crypto Trusted Service running in a Trusted Execution Environment"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::TrustedService,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(app_name, op)
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(app_name, op)
    }
}

/// Trusted Service provider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
}

impl ProviderBuilder {
    /// Create a new provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(
        mut self,
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Build into a TrustedService
    pub fn build(self) -> anyhow::Result<Provider> {
        Provider::new(self.key_info_store.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing key info store")
        })?)
    }
}
