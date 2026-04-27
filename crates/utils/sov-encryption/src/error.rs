#[derive(thiserror::Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertextFormat(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}
