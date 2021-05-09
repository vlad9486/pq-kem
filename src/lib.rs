#![forbid(unsafe_code)]
#![no_std]

use rac::{
    LineValid,
    generic_array::{ArrayLength, GenericArray},
};

pub trait Kem {
    type PublicKey: LineValid;
    type SecretKey: LineValid;
    type CipherText: LineValid;
    type PairSeedLength: ArrayLength<u8>;
    type PublicKeyHashLength: ArrayLength<u8>;
    type EncapsulationSeedLength: ArrayLength<u8>;
    type SharedSecretLength: ArrayLength<u8>;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(
        seed: &GenericArray<u8, Self::EncapsulationSeedLength>,
        public_key: &Self::PublicKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>);
    fn decapsulate(
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength>;
}
