use std::fmt::Debug;
use std::sync::Arc;

use sov_encryption::{create_encryption_layer, EncryptionLayerTrait};
use sov_rollup_interface::node::da::DaService;
use sov_rollup_interface::da::DaVerifier;


/// A generic wrapper that adds encryption to any DA service.
/// 
/// This wrapper implements the same [`DaService`] interface as the inner service,
/// but automatically encrypts data before sending to the DA layer and decrypts
/// data when reading from the DA layer.
/// 
/// # Type Parameters
/// 
/// * `T` - Must implement [`DaService`]. The inner DA service that will be wrapped with encryption.
#[derive(Clone, Debug)]
pub struct EncryptedDaService<T>
where
    T: DaService,
{
    inner: T,
    encryption: Arc<Box<dyn EncryptionLayerTrait>>,
}

impl<T> EncryptedDaService<T> 
where
    T: DaService,
{
    /// Create a new encrypted DA service wrapper
    pub fn new(inner: T, encryption_config: sov_encryption::EncryptionConfig) -> Self {
        tracing::info!("=== CREATING ENCRYPTED DA SERVICE ===");
        tracing::info!("Encryption cipher: {:?}", encryption_config.cipher_type);
        
        // Create the encryption layer from config
        let encryption = Arc::new(create_encryption_layer(encryption_config));
        
        Self {
            inner,
            encryption,
        }
    }

    /// Create with a custom encryption layer
    pub fn new_with_encryption_layer(inner: T, encryption: Box<dyn EncryptionLayerTrait>) -> Self {
        Self {
            inner,
            encryption: Arc::new(encryption),
        }
    }

    /// Get reference to the inner DA service
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get mutable reference to the inner DA service
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Extract the inner DA service
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get reference to the encryption layer
    pub fn encryption(&self) -> &Arc<Box<dyn EncryptionLayerTrait>> {
        &self.encryption
    }

    /// Create a no-op encryption configuration for passthrough mode
    fn create_noop_encryption_config() -> sov_encryption::EncryptionConfig {
        sov_encryption::EncryptionConfig {
            key_client: sov_encryption::KeyClientConfig::Static {
                encryption_key: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                decryption_key: None,
            },
            cipher_type: sov_encryption::CipherType::Aes256Gcm,
            key_rotation_interval: None,
        }
    }

    /// Create a matching encrypted DA verifier using the same encryption configuration
    /// 
    /// This method creates a verifier that uses the same encryption settings as this service
    pub fn create_matching_verifier<V>(&self, inner_verifier: V, encryption_config: Option<sov_encryption::EncryptionConfig>) -> crate::encrypted_verifier::EncryptedDaVerifier<V>
    where
        V: DaVerifier<Spec = T::Spec>,
    {
        if let Some(config) = encryption_config {
            crate::encrypted_verifier::EncryptedDaVerifier::new(inner_verifier, config)
        } else {
            // Create a no-op encryption verifier for consistency
            let noop_config = Self::create_noop_encryption_config();
            crate::encrypted_verifier::EncryptedDaVerifier::new(inner_verifier, noop_config)
        }
    }

    /// Create a new encrypted DA service from a configuration, handling both encrypted and unencrypted cases
    /// 
    /// This is a convenience method that automatically determines whether to enable encryption based on the config
    pub fn from_encrypted_config(inner_service: T, config: &crate::config::EncryptedDaConfig<T::Config>) -> Self {
        if let Some(encryption_config) = &config.encryption {
            tracing::info!("Creating encrypted DA service with encryption enabled");
            Self::new(inner_service, encryption_config.clone())
        } else {
            tracing::info!("Creating encrypted DA service without encryption (passthrough mode)");
            // Create a no-op encryption layer for consistency
            let noop_config = Self::create_noop_encryption_config();
            Self::new(inner_service, noop_config)
        }
    }

}



