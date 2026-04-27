use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use crate::error::EncryptionError;

const AES_256_KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct BatchEncryptionKey {
    material: Arc<SecretBox<Vec<u8>>>,
}

impl BatchEncryptionKey {
    pub fn from_hex(key_hex: &str) -> Result<Self, EncryptionError> {
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| EncryptionError::InvalidKeyFormat(format!("Invalid hex key: {e}")))?;

        if key_bytes.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Static encryption key must be {AES_256_KEY_SIZE} bytes, got {}",
                key_bytes.len()
            )));
        }

        if key_bytes.iter().all(|byte| *byte == 0) {
            return Err(EncryptionError::InvalidKeyFormat(
                "Static encryption key must not be all zeros".to_string(),
            ));
        }

        Ok(Self {
            material: Arc::new(SecretBox::new(Box::new(key_bytes))),
        })
    }

    pub(crate) fn expose_for_crypto(&self) -> &[u8] {
        self.material.expose_secret()
    }
}

impl std::fmt::Debug for BatchEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchEncryptionKey")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

pub trait BatchEncryptionKeyProvider: Send + Sync + std::fmt::Debug {
    fn active_key(&self) -> BatchEncryptionKey;
}

#[derive(Debug, Clone)]
pub struct StaticKeyProvider {
    key: BatchEncryptionKey,
}

impl StaticKeyProvider {
    pub fn new(key: BatchEncryptionKey) -> Self {
        Self { key }
    }
}

impl BatchEncryptionKeyProvider for StaticKeyProvider {
    fn active_key(&self) -> BatchEncryptionKey {
        self.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_key_hex() -> String {
        (0u8..32).map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn accepts_valid_static_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        assert_eq!(key.expose_for_crypto().len(), 32);
    }

    #[test]
    fn rejects_invalid_hex() {
        let err = BatchEncryptionKey::from_hex("not-hex").unwrap_err();
        assert!(err.to_string().contains("Invalid hex"));
    }

    #[test]
    fn rejects_short_key() {
        let err = BatchEncryptionKey::from_hex("abcd").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn rejects_all_zero_key() {
        let err = BatchEncryptionKey::from_hex(&"00".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("all zeros"));
    }

    #[test]
    fn debug_redacts_key_material() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&valid_key_hex()));
    }

    #[test]
    fn static_provider_returns_active_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        let provider = StaticKeyProvider::new(key.clone());
        assert_eq!(
            provider.active_key().expose_for_crypto(),
            key.expose_for_crypto()
        );
    }
}
