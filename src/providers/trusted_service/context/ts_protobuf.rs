// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::unseparated_literal_suffix,
    // There is an issue where long double become u128 in extern blocks. Check this issue:
    // https://github.com/rust-lang/rust-bindgen/issues/1549
    improper_ctypes,
    missing_debug_implementations,
    trivial_casts,
    clippy::all,
    unused,
    unused_qualifications
)]
use zeroize::Zeroize;

include!(concat!(env!("OUT_DIR"), "/ts_crypto.rs"));

/// Trait for associating an Opcode with each operation type
/// and obtaining it in a generic way.
pub trait GetOpcode {
    fn opcode(&self) -> Opcode;
}

macro_rules! opcode_impl {
    ($type:ty, $opcode:ident) => {
        impl GetOpcode for $type {
            fn opcode(&self) -> Opcode {
                Opcode::$opcode
            }
        }
    };

    ($type_in:ty, $type_out:ty, $opcode:ident) => {
        impl GetOpcode for $type_in {
            fn opcode(&self) -> Opcode {
                Opcode::$opcode
            }
        }

        impl GetOpcode for $type_out {
            fn opcode(&self) -> Opcode {
                Opcode::$opcode
            }
        }
    };
}

opcode_impl!(GenerateKeyIn, GenerateKeyOut, GenerateKey);
opcode_impl!(DestroyKeyIn, DestroyKeyOut, DestroyKey);
opcode_impl!(SignHashIn, SignHashOut, SignHash);
opcode_impl!(VerifyHashIn, VerifyHashOut, VerifyHash);
opcode_impl!(ImportKeyIn, ImportKeyOut, ImportKey);
opcode_impl!(ExportPublicKeyIn, ExportPublicKeyOut, ExportPublicKey);
opcode_impl!(AsymmetricDecryptIn, AsymmetricDecryptOut, AsymmetricDecrypt);
opcode_impl!(AsymmetricEncryptIn, AsymmetricEncryptOut, AsymmetricEncrypt);

impl Drop for ImportKeyIn {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for SignHashIn {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

impl Drop for VerifyHashIn {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.signature.zeroize();
    }
}
