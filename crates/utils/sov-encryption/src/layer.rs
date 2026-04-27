use std::sync::Arc;

#[cfg(feature = "aes-encryption")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
#[cfg(feature = "aes-encryption")]
use rand::{rngs::OsRng, RngCore};

use crate::{
    BatchEncryptionConfig, BatchEncryptionKey, BatchEncryptionKeyProvider, EncryptionError,
    StaticKeyProvider,
};

#[cfg(feature = "aes-encryption")]
const AES_256_KEY_SIZE: usize = 32;
#[cfg(feature = "aes-encryption")]
const AES_GCM_NONCE_SIZE: usize = 12;
#[cfg(feature = "aes-encryption")]
const AES_GCM_TAG_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct EncryptionLayer {
    key_provider: Arc<dyn BatchEncryptionKeyProvider>,
}

impl EncryptionLayer {
    pub fn from_config(config: BatchEncryptionConfig) -> Result<Self, EncryptionError> {
        match config {
            BatchEncryptionConfig::Static { encryption_key } => {
                let key = BatchEncryptionKey::from_hex(&encryption_key)?;
                Ok(Self::from_provider(StaticKeyProvider::new(key)))
            }
        }
    }

    pub fn from_provider(provider: impl BatchEncryptionKeyProvider + 'static) -> Self {
        Self {
            key_provider: Arc::new(provider),
        }
    }

    #[cfg(feature = "aes-encryption")]
    #[allow(deprecated)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let key = self.key_provider.active_key();
        let key = key.expose_for_crypto();
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {AES_256_KEY_SIZE} byte key, got {}",
                key.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {e}"))
        })?;

        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[cfg(feature = "aes-encryption")]
    #[allow(deprecated)]
    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let min_ciphertext_len = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
        if ciphertext_with_nonce.len() < min_ciphertext_len {
            return Err(EncryptionError::InvalidCiphertextFormat(format!(
                "Ciphertext too short: expected at least {min_ciphertext_len} bytes, got {}",
                ciphertext_with_nonce.len()
            )));
        }

        let key = self.key_provider.active_key();
        let key = key.expose_for_crypto();
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {AES_256_KEY_SIZE} byte key, got {}",
                key.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_GCM_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EncryptionError::DecryptionFailed(format!("AES-GCM decryption failed: {e}"))
        })
    }
}

#[cfg(test)]
#[cfg(feature = "aes-encryption")]
mod tests {
    use super::*;
    use crate::BatchEncryptionConfig;

    fn valid_config() -> BatchEncryptionConfig {
        BatchEncryptionConfig::Static {
            encryption_key: (1u8..=32).map(|b| format!("{b:02x}")).collect(),
        }
    }

    fn other_config() -> BatchEncryptionConfig {
        BatchEncryptionConfig::Static {
            encryption_key: (33u8..=64).map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let plaintext = b"preferred batch bytes";
        let encrypted = layer.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = layer.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_uses_random_nonce() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let plaintext = b"same plaintext";
        let first = layer.encrypt(plaintext).unwrap();
        let second = layer.encrypt(plaintext).unwrap();
        assert_ne!(first, second);
        assert_eq!(layer.decrypt(&first).unwrap(), plaintext);
        assert_eq!(layer.decrypt(&second).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let other_layer = EncryptionLayer::from_config(other_config()).unwrap();
        let encrypted = layer.encrypt(b"secret").unwrap();
        let err = other_layer.decrypt(&encrypted).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decryption failed"));
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let err = layer.decrypt(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("Ciphertext too short"));
    }

    #[test]
    fn corrupted_ciphertext_is_rejected() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let mut encrypted = layer.encrypt(b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(layer.decrypt(&encrypted).is_err());
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let encrypted = layer.encrypt(&[]).unwrap();
        assert_eq!(layer.decrypt(&encrypted).unwrap(), b"");
    }
}
