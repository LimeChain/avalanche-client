use super::error::CryptoError;
use ring::signature;

pub fn verify_pkcs1v15_signature(
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);

    public_key
        .verify(msg, signature)
        .or(Err(CryptoError::Verify))
}
