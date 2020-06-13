#![forbid(unsafe_code)]
#![no_std]

use rac::LineValid;
use generic_array::{ArrayLength, GenericArray};

pub trait Kem {
    type PublicKey: LineValid;
    type SecretKey: LineValid;
    type CipherText: LineValid;
    type PairSeedLength: ArrayLength<u8>;
    type EncapsulationSeedLength: ArrayLength<u8>;
    type SharedSecretLength: ArrayLength<u8>;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(
        seed: &GenericArray<u8, Self::EncapsulationSeedLength>,
        public_key: &Self::PublicKey,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>);
    fn decapsulate(
        secret_key: &Self::SecretKey,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength>;
}
