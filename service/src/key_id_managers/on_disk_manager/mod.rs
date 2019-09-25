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
//! A key ID manager storing key triple to key ID mapping on files on disk
//!
//! The path where the mappings should be stored is configurable. Because of possible data races,
//! there should not be two instances of this manager pointing to the same mapping folder at a time.
//! Methods modifying the mapping will also block until the modifications are done on disk to be
//! ensured to not lose mappings.
//! Because application and key names can contain any UTF-8 characters, those strings are converted
//! to base64 strings so that they can be used as filenames. Because of filenames limitations, some
//! very long UTF-8 names might not be able to be represented as a filename and will fail. For
//! example, for operating systems having a limit of 255 characters for filenames (Unix systems),
//! names will be limited to 188 bytes of UTF-8 characters.
//! For security reasons, only the PARSEC service should have the ability to modify these files.
use super::{KeyTriple, ManageKeyIDs};
use crate::authenticators::ApplicationName;
use interface::requests::ProviderID;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::fs::{DirEntry, File};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::PathBuf;

pub struct OnDiskKeyIDManager {
    /// Internal mapping, used for non-modifying operations.
    key_store: HashMap<KeyTriple, Vec<u8>>,
    /// Folder where all the key triple to key ID mappings are saved. This folder will be created
    /// if it does already exist.
    mappings_dir_path: PathBuf,
}

/// Encodes a KeyTriple's data into base64 strings that can be used as filenames.
/// The ProviderID will not be converted as a base64 as it can always be represented as a String
/// being a number from 0 and 255.
fn key_triple_to_base64_filenames(key_triple: &KeyTriple) -> (String, String, String) {
    (
        base64::encode_config(key_triple.app_name.get_name().as_bytes(), base64::URL_SAFE),
        (key_triple.provider_id as u8).to_string(),
        base64::encode_config(key_triple.key_name.as_bytes(), base64::URL_SAFE),
    )
}

/// Decodes base64 bytes to its original String value.
///
/// # Errors
///
/// Returns an error as a string if either the decoding or the bytes conversion to UTF-8 failed.
fn base64_data_to_string(base64_bytes: &[u8]) -> Result<String, String> {
    match base64::decode_config(base64_bytes, base64::URL_SAFE) {
        Ok(decode_bytes) => match String::from_utf8(decode_bytes) {
            Ok(string) => Ok(string),
            Err(error) => Err(error.to_string()),
        },
        Err(error) => Err(error.to_string()),
    }
}

/// Decodes key triple's data to the original path.
/// The Provider ID data is not converted as base64.
///
/// # Errors
///
/// Returns an error as a string if either the decoding or the bytes conversion to UTF-8 failed.
fn base64_data_triple_to_key_triple(
    app_name: &[u8],
    provider_id: ProviderID,
    key_name: &[u8],
) -> Result<KeyTriple, String> {
    let app_name = ApplicationName::new(base64_data_to_string(app_name)?);
    let key_name = base64_data_to_string(key_name)?;

    Ok(KeyTriple {
        app_name,
        provider_id,
        key_name,
    })
}

/// Converts an OsStr reference to a byte array.
///
/// # Errors
///
/// Returns a custom std::io error if the conversion failed.
fn os_str_to_u8_ref(os_str: &OsStr) -> std::io::Result<&[u8]> {
    match os_str.to_str() {
        Some(str) => Ok(str.as_bytes()),
        None => Err(Error::new(
            ErrorKind::Other,
            "Conversion from PathBuf to String failed.",
        )),
    }
}

/// Converts an OsStr reference to a ProviderID value.
///
/// # Errors
///
/// Returns a custom std::io error if the conversion failed.
fn os_str_to_provider_id(os_str: &OsStr) -> std::io::Result<ProviderID> {
    match os_str.to_str() {
        Some(str) => match str.parse::<u8>() {
            Ok(provider_id_u8) => match ProviderID::try_from(provider_id_u8) {
                Ok(provider_id) => Ok(provider_id),
                Err(response_status) => {
                    Err(Error::new(ErrorKind::Other, response_status.to_string()))
                }
            },
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "Failed to convert Provider directory name to an u8 number.",
            )),
        },
        None => Err(Error::new(
            ErrorKind::Other,
            "Conversion from PathBuf to String failed.",
        )),
    }
}

/// Lists all the directory paths in the given directory path.
fn list_dirs(path: &PathBuf) -> std::io::Result<Vec<PathBuf>> {
    // read_dir returning an iterator over Result<DirEntry>, there is first a conversion to a path
    // and then a check if the path is a directory or not.
    let dir_entries: std::io::Result<Vec<DirEntry>> = path.read_dir()?.collect();
    Ok(dir_entries?
        .iter()
        .map(|dir_entry| dir_entry.path())
        .filter(|dir_path| dir_path.is_dir())
        .collect())
}

/// Lists all the file paths in the given directory path.
fn list_files(path: &PathBuf) -> std::io::Result<Vec<PathBuf>> {
    let dir_entries: std::io::Result<Vec<DirEntry>> = path.read_dir()?.collect();
    Ok(dir_entries?
        .iter()
        .map(|dir_entry| dir_entry.path())
        .filter(|dir_path| dir_path.is_file())
        .collect())
}

impl OnDiskKeyIDManager {
    /// Creates an instance of the on-disk manager from the mapping files. This function will
    /// create the mappings directory if it does not already exist.
    /// The mappings folder is composed of three levels: two levels of directory and one level
    /// of files. The key triple to key ID mappings are represented on disk as the following:
    ///
    /// mappings_dir_path/
    /// |---app1/
    /// |   |---provider1/
    /// |   |   |---key1
    /// |   |   |---key2
    /// |   |   |   ...
    /// |   |   |---keyP
    /// |   |---provider2/
    /// |   |   ...
    /// |   |---providerM/
    /// |---app2/
    /// |   ...
    /// |---appN/
    ///
    /// where the path of a key name from the mappings directory is the key triple (application,
    /// provider, key) and the data inside the key name file is the key ID.
    /// Each mapping is contained in its own file to prevent the modification of one mapping
    /// impacting the other ones.
    ///
    /// # Errors
    ///
    /// Returns an std::io error if the function failed reading the mapping files.
    pub fn new(mappings_dir_path: PathBuf) -> std::io::Result<OnDiskKeyIDManager> {
        let mut key_store = HashMap::new();

        // Will ignore if the mappings directory already exists.
        fs::create_dir_all(&mappings_dir_path)?;

        for app_name_dir_path in list_dirs(&mappings_dir_path)?.iter() {
            for provider_dir_path in list_dirs(&app_name_dir_path)?.iter() {
                for key_name_file_path in list_files(&provider_dir_path)?.iter() {
                    println!("Found mapping file: {:?}.", key_name_file_path);
                    let mut key_id = Vec::new();
                    let mut key_id_file = File::open(&key_name_file_path)?;
                    key_id_file.read_to_end(&mut key_id)?;
                    match base64_data_triple_to_key_triple(
                        os_str_to_u8_ref(app_name_dir_path.file_name().expect(
                            "The application name directory path should contain a final component.",
                        ))?,
                        os_str_to_provider_id(provider_dir_path.file_name().expect(
                            "The provider directory path should contain a final component.",
                        ))?,
                        os_str_to_u8_ref(key_name_file_path.file_name().expect(
                            "The key name directory path should contain a final component.",
                        ))?,
                    ) {
                        Ok(key_triple) => {
                            key_store.insert(key_triple, key_id);
                        }
                        Err(string) => {
                            println!("Failed to convert the mapping path found to an UTF-8 string (error: {}).", string);
                        }
                    }
                }
            }
        }

        Ok(OnDiskKeyIDManager {
            key_store,
            mappings_dir_path,
        })
    }

    /// Saves the key triple to key ID mapping in its own file.
    /// The filename will be `mappings/[APP_NAME]/[PROVIDER_NAME]/[KEY_NAME]` under the same path as the
    /// on-disk manager. It will contain the Key ID data.
    fn save_mapping(&self, key_triple: &KeyTriple, key_id: &[u8]) -> std::io::Result<()> {
        // Create the directories with base64 names.
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let provider_dir_path = self.mappings_dir_path.join(app_name).join(prov);
        let key_name_file_path = provider_dir_path.join(key_name);
        // Will ignore if they already exist.
        fs::create_dir_all(&provider_dir_path)?;

        if key_name_file_path.exists() {
            fs::remove_file(&key_name_file_path)?;
        }

        let mut mapping_file = fs::File::create(&key_name_file_path)?;
        mapping_file.write_all(key_id)
    }

    /// Removes the mapping file.
    /// Will do nothing if the mapping file does not exist.
    fn delete_mapping(&self, key_triple: &KeyTriple) -> std::io::Result<()> {
        let (app_name, prov, key_name) = key_triple_to_base64_filenames(key_triple);
        let key_name_file_path = self
            .mappings_dir_path
            .join(app_name)
            .join(prov)
            .join(key_name);
        if key_name_file_path.exists() {
            fs::remove_file(key_name_file_path)
        } else {
            Ok(())
        }
    }
}

impl ManageKeyIDs for OnDiskKeyIDManager {
    fn get(&self, key_triple: &KeyTriple) -> Result<Option<&[u8]>, String> {
        // An Option<&Vec<u8>> can not automatically coerce to an Option<&[u8]>, it needs to be
        // done by hand.
        if let Some(key_id) = self.key_store.get(key_triple) {
            Ok(Some(key_id))
        } else {
            Ok(None)
        }
    }

    fn get_all(&self, provider_id: ProviderID) -> Result<Vec<&KeyTriple>, String> {
        Ok(self
            .key_store
            .keys()
            .filter(|key_triple| key_triple.belongs_to_provider(provider_id))
            .collect())
    }

    fn insert(
        &mut self,
        key_triple: KeyTriple,
        key_id: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        if let Err(err) = self.save_mapping(&key_triple, &key_id) {
            Err(err.to_string())
        } else {
            Ok(self.key_store.insert(key_triple, key_id))
        }
    }

    fn remove(&mut self, key_triple: &KeyTriple) -> Result<Option<Vec<u8>>, String> {
        if let Err(err) = self.delete_mapping(key_triple) {
            Err(err.to_string())
        } else if let Some(key_id) = self.key_store.remove(key_triple) {
            Ok(Some(key_id))
        } else {
            Ok(None)
        }
    }

    fn exists(&self, key_triple: &KeyTriple) -> Result<bool, String> {
        Ok(self.key_store.contains_key(key_triple))
    }
}

#[cfg(test)]
mod test {
    use super::super::{KeyTriple, ManageKeyIDs};
    use super::OnDiskKeyIDManager;
    use crate::authenticators::ApplicationName;
    use interface::requests::ProviderID;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn insert_get_key_id() {
        let path = PathBuf::from("target/insert_get_key_id_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_get_key_id".to_string());
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(manager.get(&key_triple).unwrap().is_none());

        assert!(manager
            .insert(key_triple.clone(), key_id.clone())
            .unwrap()
            .is_none());

        let stored_key_id = Vec::from(
            manager
                .get(&key_triple)
                .unwrap()
                .expect("Failed to get key id"),
        );

        assert_eq!(stored_key_id, key_id);
        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_remove_key() {
        let path = PathBuf::from("target/insert_remove_key_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_remove_key".to_string());
        let key_id = vec![0x11, 0x22, 0x33];

        manager.insert(key_triple.clone(), key_id.clone()).unwrap();

        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn remove_unexisting_key() {
        let path = PathBuf::from("target/remove_unexisting_key_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("remove_unexisting_key".to_string());
        assert_eq!(manager.remove(&key_triple).unwrap(), None);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exists() {
        let path = PathBuf::from("target/exists_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("exists".to_string());
        let key_id = vec![0x11, 0x22, 0x33];

        assert!(!manager.exists(&key_triple).unwrap());

        manager.insert(key_triple.clone(), key_id.clone()).unwrap();
        assert!(manager.exists(&key_triple).unwrap());

        manager.remove(&key_triple).unwrap();
        assert!(!manager.exists(&key_triple).unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn insert_overwrites() {
        let path = PathBuf::from("target/insert_overwrites_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let key_triple = new_key_triple("insert_overwrites".to_string());
        let key_id_1 = vec![0x11, 0x22, 0x33];
        let key_id_2 = vec![0xaa, 0xbb, 0xcc];

        manager
            .insert(key_triple.clone(), key_id_1.clone())
            .unwrap();
        manager
            .insert(key_triple.clone(), key_id_2.clone())
            .unwrap();

        let stored_key_id = Vec::from(
            manager
                .get(&key_triple)
                .unwrap()
                .expect("Failed to get key id"),
        );

        assert_eq!(stored_key_id, key_id_2);
        assert!(manager.remove(&key_triple).unwrap().is_some());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_ascii() {
        let path = PathBuf::from("target/big_names_ascii_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let big_app_name_ascii = ApplicationName::new("  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string());
        let big_key_name_ascii = "  Lorem ipsum dolor sit amet, ei suas viris sea, deleniti repudiare te qui. Natum paulo decore ut nec, ne propriae offendit adipisci has. Eius clita legere mel at, ei vis minimum tincidunt.".to_string();

        let key_triple = KeyTriple::new(
            big_app_name_ascii,
            ProviderID::CoreProvider,
            big_key_name_ascii,
        );
        let key_id = vec![0x11, 0x22, 0x33];

        manager.insert(key_triple.clone(), key_id.clone()).unwrap();
        assert_eq!(manager.remove(&key_triple).unwrap().unwrap(), key_id);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn big_names_emoticons() {
        let path = PathBuf::from("target/big_names_emoticons_mappings");
        let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

        let big_app_name_emoticons = ApplicationName::new("😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string());
        let big_key_name_emoticons = "😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮".to_string();

        let key_triple = KeyTriple::new(
            big_app_name_emoticons,
            ProviderID::MbedProvider,
            big_key_name_emoticons,
        );
        let key_id = vec![0x11, 0x22, 0x33];

        manager.insert(key_triple.clone(), key_id.clone()).unwrap();
        assert_eq!(manager.remove(&key_triple).unwrap().unwrap(), key_id);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn create_and_load() {
        let path = PathBuf::from("target/create_and_load_mappings");

        let app_name1 = ApplicationName::new("😀 Application One 😀".to_string());
        let key_name1 = "😀 Key One 😀".to_string();
        let key_triple1 = KeyTriple::new(app_name1, ProviderID::CoreProvider, key_name1);
        let key_id1 = vec![0x11, 0x22, 0x33];

        let app_name2 = ApplicationName::new("😇 Application Two 😇".to_string());
        let key_name2 = "😇 Key Two 😇".to_string();
        let key_triple2 = KeyTriple::new(app_name2, ProviderID::MbedProvider, key_name2);
        let key_id2 = vec![0x12, 0x22, 0x32];

        let app_name3 = ApplicationName::new("😈 Application Three 😈".to_string());
        let key_name3 = "😈 Key Three 😈".to_string();
        let key_triple3 = KeyTriple::new(app_name3, ProviderID::CoreProvider, key_name3);
        let key_id3 = vec![0x13, 0x23, 0x33];
        {
            let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

            manager
                .insert(key_triple1.clone(), key_id1.clone())
                .unwrap();
            manager
                .insert(key_triple2.clone(), key_id2.clone())
                .unwrap();
            manager
                .insert(key_triple3.clone(), key_id3.clone())
                .unwrap();
        }
        // The local hashmap is dropped when leaving the inner scope.
        {
            let mut manager = OnDiskKeyIDManager::new(path.clone()).unwrap();

            assert_eq!(manager.remove(&key_triple1).unwrap().unwrap(), key_id1);
            assert_eq!(manager.remove(&key_triple2).unwrap().unwrap(), key_id2);
            assert_eq!(manager.remove(&key_triple3).unwrap().unwrap(), key_id3);
        }

        fs::remove_dir_all(path).unwrap();
    }

    fn new_key_triple(key_name: String) -> KeyTriple {
        KeyTriple::new(
            ApplicationName::new("Testing Application 😎".to_string()),
            ProviderID::MbedProvider,
            key_name,
        )
    }
}
