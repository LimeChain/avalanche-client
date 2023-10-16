use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Failed to create a EcdsaKeyPair")]
    EcdsaKeyPairRejected(#[from] ring::error::KeyRejected),
    #[error("Failed to sign message")]
    Sign,
    #[error("Failed to verify message")]
    Verify,
}
