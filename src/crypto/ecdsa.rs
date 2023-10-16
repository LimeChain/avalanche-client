use std::ops::Deref;

use super::error::CryptoError;
use super::RANDOM;
use ring::signature::{self, Signature};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

pub fn verify_signature(
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key);

    public_key
        .verify(msg, signature)
        .or(Err(CryptoError::Verify))
}

pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Signature, CryptoError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        private_key,
        RANDOM.deref(),
    )?;
    let sig = key_pair
        .sign(RANDOM.deref(), message)
        .or(Err(CryptoError::Sign))?;
    Ok(sig)
}
