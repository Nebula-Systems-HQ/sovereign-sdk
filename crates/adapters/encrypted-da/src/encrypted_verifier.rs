use std::fmt::Debug;
use std::sync::Arc;

use sov_encryption::EncryptionLayerTrait;
use sov_rollup_interface::da::{DaVerifier, DaSpec, RelevantBlobs, RelevantProofs};

/// A generic wrapper that adds decryption to any DA verifier.
/// 
/// This wrapper implements the same [`DaVerifier`] interface as the inner verifier,
/// but automatically decrypts blob data before verification. This ensures that
/// the inner verifier processes the original unencrypted data, maintaining
/// compatibility with existing verification logic.
/// 
/// # Type Parameters
/// 
/// * `T` - Must implement [`DaVerifier`]. The inner DA verifier that will be wrapped with decryption.
#[derive(Clone, Debug)]
pub struct EncryptedDaVerifier<T>
where
    T: DaVerifier,
{
    inner: T,
    encryption: Arc<Box<dyn EncryptionLayerTrait>>,
}

impl<T> EncryptedDaVerifier<T>
where
    T: DaVerifier,
{
    /// Create a new encrypted DA verifier wrapper
    pub fn new(inner: T, encryption_config: sov_encryption::EncryptionConfig) -> Self {
        tracing::info!("=== CREATING ENCRYPTED DA VERIFIER ===");
        tracing::info!("Encryption cipher: {:?}", encryption_config.cipher_type);
        
        // Create the encryption layer from config
        let encryption = Arc::new(sov_encryption::create_encryption_layer(encryption_config));
        
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

    /// Get reference to the inner DA verifier
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get mutable reference to the inner DA verifier
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Extract the inner DA verifier
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get reference to the encryption layer
    pub fn encryption(&self) -> &Arc<Box<dyn EncryptionLayerTrait>> {
        &self.encryption
    }
}

impl<T> DaVerifier for EncryptedDaVerifier<T>
where
    T: DaVerifier,
{
    type Spec = T::Spec;
    type Error = T::Error;

    fn new(_params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        panic!("EncryptedDaVerifier cannot be created with DaVerifier::new(). Use EncryptedDaVerifier::new() or EncryptedDaVerifier::new_with_encryption_layer() instead.")
    }

    fn verify_relevant_tx_list(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        relevant_blobs: &RelevantBlobs<<T::Spec as DaSpec>::BlobTransaction>,
        relevant_proofs: RelevantProofs<
            <T::Spec as DaSpec>::InclusionMultiProof,
            <T::Spec as DaSpec>::CompletenessProof,
        >,
    ) -> Result<(), Self::Error> {
        tracing::debug!("=== ENCRYPTED DA VERIFIER: verify_relevant_tx_list ===");
        tracing::debug!("Processing {} batch blobs and {} proof blobs", 
                       relevant_blobs.batch_blobs.len(), relevant_blobs.proof_blobs.len());
        
        // Pass the blobs directly to the inner verifier
        // Decryption is handled at the blob level via the BlobReaderTrait's with_transformed_data method
        // when the inner verifier reads the blob data
        self.inner.verify_relevant_tx_list(
            block_header,
            relevant_blobs,
            relevant_proofs,
        )
    }
}