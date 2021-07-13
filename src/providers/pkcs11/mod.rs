// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS 11 provider
//!
//! This provider allows clients to access any PKCS 11 compliant device
//! through the Parsec interface.
use super::Provide;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::{KeyInfoManagerClient, KeyTriple};
use cryptoki::types::locking::CInitializeArgs;
use cryptoki::types::session::{Session, UserType};
use cryptoki::types::slot_token::Slot;
use cryptoki::types::Flags;
use cryptoki::Pkcs11;
use derivative::Derivative;
use log::{error, info, trace, warn};
use parsec_interface::operations::{list_clients, list_keys, list_providers::ProviderInfo};
use parsec_interface::operations::{
    psa_asymmetric_decrypt, psa_asymmetric_encrypt, psa_destroy_key, psa_export_public_key,
    psa_generate_key, psa_import_key, psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use parsec_interface::secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;
use std::convert::TryInto;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::RwLock;
use utils::{to_response_status, KeyPairType};
use uuid::Uuid;
use zeroize::Zeroize;

type LocalIdStore = HashSet<u32>;

mod asym_encryption;
mod asym_sign;
mod key_management;
mod key_metadata;
mod utils;

const SUPPORTED_OPCODES: [Opcode; 8] = [
    Opcode::PsaGenerateKey,
    Opcode::PsaDestroyKey,
    Opcode::PsaSignHash,
    Opcode::PsaVerifyHash,
    Opcode::PsaImportKey,
    Opcode::PsaExportPublicKey,
    Opcode::PsaAsymmetricDecrypt,
    Opcode::PsaAsymmetricEncrypt,
];

/// Provider for Public Key Cryptography Standard #11
///
/// Operations for this provider are serviced through a PKCS11 interface,
/// allowing any libraries exposing said interface to be loaded and used
/// at runtime.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Provider {
    #[derivative(Debug = "ignore")]
    key_info_store: KeyInfoManagerClient,
    local_ids: RwLock<LocalIdStore>,
    #[derivative(Debug = "ignore")]
    backend: Pkcs11,
    slot_number: Slot,
    software_public_operations: bool,
    allow_export: bool,
}

impl Provider {
    /// Creates and initialise a new instance of Pkcs11Provider.
    /// Checks if there are not more keys stored in the Key Info Manager than in the PKCS 11 library
    /// and if there are, delete them. Adds Key IDs currently in use in the local IDs store.
    /// Returns `None` if the initialisation failed.
    fn new(
        key_info_store: KeyInfoManagerClient,
        backend: Pkcs11,
        slot_number: Option<Slot>,
        user_pin: Option<SecretString>,
        software_public_operations: bool,
        allow_export: bool,
    ) -> Option<Provider> {
        // If slot_number is not valid take the first available with a valid token
        let slot_number = match slot_number {
            Some(i) => i,
            None => {
                let slots = backend.get_slots_with_token().ok()?;
                if !slots.is_empty() {
                    slots[0]
                } else {
                    return None;
                }
            }
        };

        if let Some(pin) = user_pin {
            backend.set_pin(slot_number, pin.expose_secret()).ok()?;
        }

        #[allow(clippy::mutex_atomic)]
        let pkcs11_provider = Provider {
            key_info_store,
            local_ids: RwLock::new(HashSet::new()),
            backend,
            slot_number,
            software_public_operations,
            allow_export,
        };
        {
            let mut local_ids_handle = pkcs11_provider
                .local_ids
                .write()
                .expect("Local ID lock poisoned");
            let mut to_remove: Vec<KeyTriple> = Vec::new();
            // Go through all PKCS 11 key triple to key info mappings and check if they are still
            // present.
            // Delete those who are not present and add to the local_store the ones present.
            match pkcs11_provider.key_info_store.get_all() {
                Ok(key_triples) => {
                    let session = pkcs11_provider.new_session().ok()?;

                    for key_triple in key_triples.iter().cloned() {
                        let key_id = match pkcs11_provider.key_info_store.get_key_id(&key_triple) {
                            Ok(id) => id,
                            Err(ResponseStatus::PsaErrorDoesNotExist) => {
                                error!("Stored key info missing for key triple {}.", key_triple);
                                continue;
                            }
                            Err(e) => {
                                format_error!(
                                    format!(
                                        "Stored key info invalid for key triple {}.",
                                        key_triple
                                    ),
                                    e
                                );

                                to_remove.push(key_triple.clone());
                                continue;
                            }
                        };

                        match pkcs11_provider.find_key(&session, key_id, KeyPairType::Any) {
                            Ok(_) => {
                                if crate::utils::GlobalConfig::log_error_details() {
                                    warn!(
                                        "Key {} found in the PKCS 11 library, adding it.",
                                        key_triple
                                    );
                                } else {
                                    warn!("Key found in the PKCS 11 library, adding it.");
                                }
                                let _ = local_ids_handle.insert(key_id);
                            }
                            Err(ResponseStatus::PsaErrorDoesNotExist) => {
                                if crate::utils::GlobalConfig::log_error_details() {
                                    warn!(
                                        "Key {} not found in the PKCS 11 library, deleting it.",
                                        key_triple
                                    );
                                } else {
                                    warn!("Key not found in the PKCS 11 library, deleting it.");
                                }
                                to_remove.push(key_triple.clone());
                            }
                            Err(e) => {
                                format_error!("Error finding key objects", e);
                                return None;
                            }
                        }
                    }
                }
                Err(string) => {
                    format_error!("Key Info Manager error", string);
                    return None;
                }
            };
            for key_triple in to_remove.iter() {
                if pkcs11_provider
                    .key_info_store
                    .remove_key_info(&key_triple)
                    .is_err()
                {
                    return None;
                }
            }
        }

        if pkcs11_provider.software_public_operations {
            psa_crypto::init().expect(
                "Failed to initialize PSA Crypto for public key operation software support",
            );
        }

        Some(pkcs11_provider)
    }

    // Create a new session with the following properties:
    // * without callback
    // * read/write session
    // * serial session
    // * logged in if the pin is set
    // * set on the slot in the provider
    fn new_session(&self) -> Result<Session> {
        let mut flags = Flags::new();
        let _ = flags.set_rw_session(true).set_serial_session(true);

        let session = self
            .backend
            .open_session_no_callback(self.slot_number, flags)
            .map_err(to_response_status)?;

        session.login(UserType::User).map_err(to_response_status)?;

        Ok(session)
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((
            ProviderInfo {
                // Assigned UUID for this provider: 30e39502-eba6-4d60-a4af-c518b7f5e38f
                uuid: Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f")
                    .or(Err(ResponseStatus::InvalidEncoding))?,
                description: String::from(
                    "PKCS #11 provider, interfacing with a PKCS #11 library.",
                ),
                vendor: String::from("OASIS Standard."),
                version_maj: 0,
                version_min: 1,
                version_rev: 0,
                id: ProviderId::Pkcs11,
            },
            SUPPORTED_OPCODES.iter().copied().collect(),
        ))
    }

    fn list_keys(
        &self,
        app_name: ApplicationName,
        _op: list_keys::Operation,
    ) -> Result<list_keys::Result> {
        trace!("list_keys ingress");
        Ok(list_keys::Result {
            keys: self.key_info_store.list_keys(&app_name)?,
        })
    }

    fn list_clients(&self, _op: list_clients::Operation) -> Result<list_clients::Result> {
        trace!("list_clients ingress");
        Ok(list_clients::Result {
            clients: self
                .key_info_store
                .list_clients()?
                .into_iter()
                .map(|app_name| app_name.to_string())
                .collect(),
        })
    }

    fn psa_generate_key(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        trace!("psa_generate_key ingress");
        self.psa_generate_key_internal(app_name, op)
    }

    fn psa_import_key(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        trace!("psa_import_key ingress");
        self.psa_import_key_internal(app_name, op)
    }

    fn psa_export_public_key(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        trace!("psa_export_public_key ingress");
        self.psa_export_public_key_internal(app_name, op)
    }

    fn psa_destroy_key(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        trace!("psa_destroy_key ingress");
        self.psa_destroy_key_internal(app_name, op)
    }

    fn psa_sign_hash(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        trace!("psa_sign_hash ingress");
        self.psa_sign_hash_internal(app_name, op)
    }

    fn psa_verify_hash(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        if self.software_public_operations {
            trace!("software_psa_verify_hash ingress");
            self.software_psa_verify_hash_internal(app_name, op)
        } else {
            trace!("pkcs11_psa_verify_hash ingress");
            self.psa_verify_hash_internal(app_name, op)
        }
    }

    fn psa_asymmetric_encrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_encrypt::Operation,
    ) -> Result<psa_asymmetric_encrypt::Result> {
        if self.software_public_operations {
            trace!("software_psa_asymmetric_encrypt ingress");
            self.software_psa_asymmetric_encrypt_internal(app_name, op)
        } else {
            trace!("psa_asymmetric_encrypt ingress");
            self.psa_asymmetric_encrypt_internal(app_name, op)
        }
    }

    fn psa_asymmetric_decrypt(
        &self,
        app_name: ApplicationName,
        op: psa_asymmetric_decrypt::Operation,
    ) -> Result<psa_asymmetric_decrypt::Result> {
        trace!("psa_asymmetric_decrypt ingress");
        self.psa_asymmetric_decrypt_internal(app_name, op)
    }
}

/// Builder for Pkcs11Provider
///
/// This builder contains some confidential information that is passed to the Pkcs11Provider. The
/// Pkcs11Provider will zeroize this data when dropping. This data will not be cloned when
/// building.
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<KeyInfoManagerClient>,
    pkcs11_library_path: Option<String>,
    slot_number: Option<u64>,
    user_pin: Option<SecretString>,
    software_public_operations: Option<bool>,
    allow_export: Option<bool>,
}

impl ProviderBuilder {
    /// Create a new Pkcs11Provider builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
            pkcs11_library_path: None,
            slot_number: None,
            user_pin: None,
            software_public_operations: None,
            allow_export: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(mut self, key_info_store: KeyInfoManagerClient) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the path of the PKCS11 library
    pub fn with_pkcs11_library_path(mut self, pkcs11_library_path: String) -> ProviderBuilder {
        self.pkcs11_library_path = Some(pkcs11_library_path);

        self
    }

    /// Specify the slot number used
    pub fn with_slot_number(mut self, slot_number: u64) -> ProviderBuilder {
        self.slot_number = Some(slot_number);

        self
    }

    /// Specify the user pin
    pub fn with_user_pin(mut self, mut user_pin: Option<String>) -> ProviderBuilder {
        self.user_pin = match user_pin {
            // The conversion form a String is infallible.
            Some(ref pin) => Some(SecretString::from_str(&pin).unwrap()),
            None => None,
        };
        user_pin.zeroize();

        self
    }

    /// Specify the `software_public_operations` flag
    pub fn with_software_public_operations(
        mut self,
        software_public_operations: Option<bool>,
    ) -> ProviderBuilder {
        self.software_public_operations = software_public_operations;

        self
    }

    /// Specify the `allow_export` flag
    pub fn with_allow_export(mut self, allow_export: Option<bool>) -> ProviderBuilder {
        self.allow_export = allow_export;

        self
    }

    /// Attempt to build a PKCS11 provider
    pub fn build(self) -> std::io::Result<Provider> {
        let library_path = self
            .pkcs11_library_path
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing library path"))?;
        info!(
            "Building a PKCS 11 provider with library \'{}\'",
            library_path
        );
        let slot_number = self
            .slot_number
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing slot number"))?;
        let slot = slot_number.try_into().or_else(|_| {
            Err(Error::new(
                ErrorKind::InvalidData,
                "cannot convert slot value",
            ))
        })?;

        let backend = Pkcs11::new(library_path).map_err(|e| {
            format_error!("Error creating a PKCS 11 context", e);
            Error::new(ErrorKind::InvalidData, "error creating PKCS 11 context")
        })?;
        trace!("Initialize command");
        backend
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| {
                format_error!("Error initializing PKCS 11 context", e);
                Error::new(ErrorKind::InvalidData, "error initializing PKCS 11 context")
            })?;

        Ok(Provider::new(
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            backend,
            Some(slot),
            self.user_pin,
            self.software_public_operations.unwrap_or(false),
            self.allow_export.unwrap_or(true),
        )
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "PKCS 11 initialization failed"))?)
    }
}
