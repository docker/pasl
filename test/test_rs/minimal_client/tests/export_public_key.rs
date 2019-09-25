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
#[cfg(test)]
mod tests {
    use interface::operations::key_attributes::*;
    use interface::operations::{
        NativeOperation, NativeResult, OpCreateKey, OpDestroyKey, OpExportPublicKey, OpImportKey,
    };
    use interface::requests::ProviderID;
    use interface::requests::ResponseStatus;
    use minimal_client::MinimalClient;

    #[test]
    fn export_public_key() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let create_key = OpCreateKey {
            key_name: String::from("export_public_key"),
            key_attributes: KeyAttributes {
                key_lifetime: KeyLifetime::Persistent,
                key_type: KeyType::RsaKeypair,
                ecc_curve: None,
                algorithm: Algorithm::sign(SignAlgorithm::RsaPkcs1v15Sign, None),
                key_size: 1024,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
        };
        client
            .send_operation(NativeOperation::CreateKey(create_key))
            .unwrap();

        let export = OpExportPublicKey {
            key_name: String::from("export_public_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(NativeOperation::ExportPublicKey(export))
            .unwrap();

        let destroy_key = OpDestroyKey {
            key_name: String::from("export_public_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(NativeOperation::DestroyKey(destroy_key))
            .unwrap();
    }

    #[test]
    fn export_without_create() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let export = OpExportPublicKey {
            key_name: String::from("export_without_create"),
            key_lifetime: KeyLifetime::Persistent,
        };
        let status = client
            .send_operation(NativeOperation::ExportPublicKey(export))
            .expect_err("Key should not exist.");
        assert_eq!(status, ResponseStatus::KeyDoesNotExist);
    }

    #[test]
    fn import_and_export_public_key() {
        let mut client = MinimalClient::new(ProviderID::MbedProvider);
        let key_data = vec![
            48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247,
            20, 102, 253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109,
            16, 81, 135, 72, 112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239,
            93, 5, 203, 185, 233, 61, 159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150,
            168, 156, 212, 6, 63, 81, 24, 101, 72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228,
            178, 252, 35, 209, 222, 228, 16, 143, 99, 143, 146, 241, 186, 187, 22, 209, 86, 141,
            24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28, 39, 22, 141, 173, 85, 26, 58, 9,
            128, 27, 57, 131, 2, 3, 1, 0, 1,
        ];
        let import = OpImportKey {
            key_name: String::from("import_and_export_public_key"),
            key_attributes: KeyAttributes {
                key_lifetime: KeyLifetime::Persistent,
                key_type: KeyType::RsaPublicKey,
                ecc_curve: None,
                algorithm: Algorithm::sign(SignAlgorithm::RsaPkcs1v15Sign, None),
                key_size: key_data.len() as u32,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
            key_data: key_data.clone(),
        };
        client
            .send_operation(NativeOperation::ImportKey(import))
            .unwrap();

        let export = OpExportPublicKey {
            key_name: String::from("import_and_export_public_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        let convert_result = client
            .send_operation(NativeOperation::ExportPublicKey(export))
            .unwrap();
        if let NativeResult::ExportPublicKey(result) = convert_result {
            assert_eq!(key_data, result.key_data);
        }

        let destroy_key = OpDestroyKey {
            key_name: String::from("import_and_export_public_key"),
            key_lifetime: KeyLifetime::Persistent,
        };
        client
            .send_operation(NativeOperation::DestroyKey(destroy_key))
            .unwrap();
    }
}
