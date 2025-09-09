use std::fmt::Display;

use async_trait::async_trait;

// Simple error type for blob transformation that satisfies the trait bounds
#[cfg(feature = "native")]
#[derive(Debug)]
struct TransformError(String);

#[cfg(feature = "native")]
impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "native")]
impl std::error::Error for TransformError {}
use sov_rollup_interface::da::{
    BlobReaderTrait, DaSpec, RelevantBlobs, RelevantProofs, 
};
use sov_rollup_interface::node::da::{DaService, SubmitBlobReceipt};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::config::EncryptedDaConfig;
use crate::filtered_block::EncryptedFilteredBlock;
use crate::encrypted_service::EncryptedDaService;

/// Implementation of the DaService trait for the EncryptedDaService<T> wrapper
/// 
/// This implementation allows for encryption/decryption of data stored on Data Availability layers without any API changes.
/// 
/// The wrapper delegates most functionality to the inner DA service, but adds 
/// encryption/decryption of data using the sov-encryption layer.
/// 
/// # Type Parameters
/// 
/// * `T` - Must implement [`DaService`]. The inner DA service that will be wrapped with encryption.
#[async_trait]
impl<T> DaService for EncryptedDaService<T>
where
    T: DaService + Clone + Send + Sync + 'static,
    T::Error: Send + Sync + Display,
    <<T as DaService>::Spec as DaSpec>::BlobTransaction: BlobReaderTrait,
{
    type Spec = T::Spec;
    type Config = EncryptedDaConfig<T::Config>;
    type Verifier = T::Verifier;
    type FilteredBlock = EncryptedFilteredBlock<T::FilteredBlock>;
    type Error = anyhow::Error;

    const GUARANTEES_TRANSACTION_ORDERING: bool = T::GUARANTEES_TRANSACTION_ORDERING;

    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        debug!("Getting block at height {}", height);
        
        // Get the FilteredBlock from the inner DA service at the given height
        let inner_block = self.inner()
            .get_block_at(height)
            .await
            .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))?;

        // Just wrap the block without eager decryption - decryption will happen lazily
        // when extract_relevant_blobs() is called
        tracing::info!("Retrieved block at height {} - will decrypt lazily when blobs are extracted", height);
        let wrapped_block = EncryptedFilteredBlock::new(inner_block, self.encryption().clone()).await?;
        
        debug!("Successfully retrieved block at height {}", height);
        Ok(wrapped_block)
    }

    async fn get_block_header_at(
        &self,
        height: u64,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        debug!("Getting block header at height {}", height);
        
        // Delegate to the inner DA service to get the block header
        self.inner()
            .get_block_header_at(height)
            .await
            .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))
    }

    async fn get_last_finalized_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        debug!("Getting last finalized block header");
        
        // Delegate to the inner DA service to get the block header
        self.inner()
            .get_last_finalized_block_header()
            .await
            .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))
    }

    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        debug!("Getting head block header");
        
        // Delegate to the inner DA service to get the block header
        self.inner()
            .get_head_block_header()
            .await
            .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))
    }

    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction> {
        
        // Extract blobs from the inner block - these contain encrypted data
        let mut inner_blobs = self.inner().extract_relevant_blobs(block.inner());
        
        tracing::info!("=== LAZY DECRYPTION ===");
        
        // Calculate lengths before mutable iteration to avoid borrowing conflicts
        let batch_blobs_count = inner_blobs.batch_blobs.len();
        let proof_blobs_count = inner_blobs.proof_blobs.len();
        
        tracing::info!("Extracting {} batch blobs and {} proof blobs - decrypting on demand", 
                      batch_blobs_count, proof_blobs_count);
        
        // Decrypt batch blobs lazily using tokio::runtime::Handle::current()
        for (i, blob) in inner_blobs.batch_blobs.iter_mut().enumerate() {
            tracing::info!("Starting lazy decryption of batch blob {} of {}", i + 1, batch_blobs_count);
            let original_data_len = blob.total_len();
            tracing::info!("Original blob size: {} bytes", original_data_len);
            
            #[cfg(feature = "native")]
            {
                use sov_rollup_interface::da::BlobReaderTrait as _;
                let encryption = self.encryption().clone();
                let decrypt_result = blob.with_transformed_data(|encrypted_data| -> Result<Vec<u8>, TransformError> {
                    tracing::info!("About to decrypt {} bytes of data", encrypted_data.len());
                    // Use futures executor to run async decryption in sync context
                    // This works better than tokio's block_on when already in an async context
                    let result = futures::executor::block_on(async {
                        encryption.decrypt(encrypted_data).await
                            .map_err(|e| TransformError(format!("Lazy decryption failed: {}", e)))
                    });
                    tracing::info!("Decryption result: {:?}", result.as_ref().map(|d| d.len()).map_err(|e| e.to_string()));
                    result
                });
                
                match decrypt_result {
                    Ok(()) => {
                        let new_data_len = blob.total_len();
                        tracing::info!("Successfully decrypted batch blob {} - size changed from {} to {} bytes", i, original_data_len, new_data_len);
                    }
                    Err(e) => {
                        tracing::error!("Failed to decrypt batch blob {} lazily: {}", i, e);
                    }
                }
            }
            
            #[cfg(not(feature = "native"))]
            {
                tracing::warn!("Native feature not enabled - skipping decryption");
                // Suppress unused variable warning when native feature is not enabled
                let _ = blob;
            }
        }
        
        // Decrypt proof blobs lazily
        for (i, blob) in inner_blobs.proof_blobs.iter_mut().enumerate() {
            tracing::debug!("Decrypting proof blob {} on demand", i + 1);
            
            #[cfg(feature = "native")]
            {
                use sov_rollup_interface::da::BlobReaderTrait as _;
                let encryption = self.encryption().clone();
                let decrypt_result = blob.with_transformed_data(|encrypted_data| -> Result<Vec<u8>, TransformError> {
                    // Use futures executor to run async decryption in sync context
                    // This works better than tokio's block_on when already in an async context
                    futures::executor::block_on(async {
                        encryption.decrypt(encrypted_data).await
                            .map_err(|e| TransformError(format!("Lazy decryption failed: {}", e)))
                    })
                });
                
                if let Err(e) = decrypt_result {
                    tracing::warn!("Failed to decrypt proof blob {} lazily: {}", i, e);
                }
            }
            
            #[cfg(not(feature = "native"))]
            {
                // Suppress unused variable warning when native feature is not enabled
                let _ = blob;
            }
        }
        
        tracing::info!("=== LAZY DECRYPTION COMPLETE ===");
        tracing::info!("Successfully extracted blobs with lazily decrypted data");
        inner_blobs
    }

    async fn get_extraction_proof(
        &self,
        block: &Self::FilteredBlock,
        blobs: &RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction>,
    ) -> RelevantProofs<
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    > {
        // Delegate to the inner DA service to get the extraction proof
        self.inner().get_extraction_proof(block.inner(), blobs).await
    }

    async fn send_transaction(
        &self,
        blob: &[u8],
    ) -> oneshot::Receiver<
        Result<SubmitBlobReceipt<<Self::Spec as DaSpec>::TransactionId>, Self::Error>,
    > {
        tracing::info!("=== ENCRYPTING TRANSACTION ===");
        tracing::info!("Original blob size: {} bytes", blob.len());
        tracing::info!("Original blob (first 32 bytes): {}", hex::encode(&blob[..std::cmp::min(32, blob.len())]));
        debug!("Sending encrypted transaction of {} bytes", blob.len());
        
        let (tx, rx) = oneshot::channel();
        
        // Encrypt the blob before sending
        let encryption = self.encryption().clone();
        let blob_to_encrypt = blob.to_vec();
        let inner_service = self.inner().clone();
        
        tokio::spawn(async move {
            let result: Result<SubmitBlobReceipt<<T::Spec as DaSpec>::TransactionId>, anyhow::Error> = async {
                let encrypted_blob = encryption.encrypt(&blob_to_encrypt).await
                    .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
                tracing::info!("Encrypted blob from {} to {} bytes", blob_to_encrypt.len(), encrypted_blob.len());
                tracing::info!("Encrypted blob (first 32 bytes): {}", hex::encode(&encrypted_blob[..std::cmp::min(32, encrypted_blob.len())]));
                tracing::info!("=== ENCRYPTION COMPLETE ===");
                debug!("Encrypted blob from {} to {} bytes", blob_to_encrypt.len(), encrypted_blob.len());
                
                let inner_receiver = inner_service
                    .send_transaction(&encrypted_blob)
                    .await;
                let inner_result = inner_receiver
                    .await
                    .map_err(|e| anyhow::anyhow!("Channel error: {}", e))?;
                let inner_receipt = inner_result
                    .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))?;
                
                Ok(inner_receipt)
            }.await;
            
            let _ = tx.send(result);
        });
        
        rx
    }

    async fn send_proof(
        &self,
        aggregated_proof_data: &[u8],
    ) -> oneshot::Receiver<
        Result<SubmitBlobReceipt<<Self::Spec as DaSpec>::TransactionId>, Self::Error>,
    > {
        debug!("Sending encrypted proof of {} bytes", aggregated_proof_data.len());
        
        let (tx, rx) = oneshot::channel();
        
        // Encrypt the proof before sending
        let encryption = self.encryption().clone();
        let proof_to_encrypt = aggregated_proof_data.to_vec();
        let inner_service = self.inner().clone();
        
        tokio::spawn(async move {
            let result: Result<SubmitBlobReceipt<<T::Spec as DaSpec>::TransactionId>, anyhow::Error> = async {
                let encrypted_proof = encryption.encrypt(&proof_to_encrypt).await
                    .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
                debug!("Encrypted proof from {} to {} bytes", proof_to_encrypt.len(), encrypted_proof.len());
                
                let inner_receiver = inner_service
                    .send_proof(&encrypted_proof)
                    .await;
                let inner_result = inner_receiver
                    .await
                    .map_err(|e| anyhow::anyhow!("Channel error: {}", e))?;
                let inner_receipt = inner_result
                    .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))?;
                
                Ok(inner_receipt)
            }.await;
            
            let _ = tx.send(result);
        });
        
        rx
    }

    async fn get_proofs_at(&self, height: u64) -> Result<Vec<Vec<u8>>, Self::Error> {
        tracing::info!("=== DECRYPTING PROOFS ===");
        tracing::info!("Getting encrypted proofs at height {}", height);
        debug!("Getting encrypted proofs at height {}", height);
        
        let encrypted_proofs = self.inner()
            .get_proofs_at(height)
            .await
            .map_err(|e| anyhow::anyhow!("Inner DA service error: {}", e))?;

        let mut decrypted_proofs = Vec::with_capacity(encrypted_proofs.len());
        
        for (i, encrypted_proof) in encrypted_proofs.iter().enumerate() {
            tracing::info!("Decrypting proof {} of {}", i + 1, encrypted_proofs.len());
            tracing::info!("Encrypted proof size: {} bytes", encrypted_proof.len());
            tracing::info!("Encrypted proof (first 32 bytes): {}", hex::encode(&encrypted_proof[..std::cmp::min(32, encrypted_proof.len())]));
            
            let decrypted_proof = self.encryption()
                .decrypt(encrypted_proof)
                .await
                .map_err(|e| anyhow::anyhow!("Decryption error: {}", e))?;
            
            tracing::info!("Decrypted proof size: {} bytes", decrypted_proof.len());
            tracing::info!("Decrypted proof (first 32 bytes): {}", hex::encode(&decrypted_proof[..std::cmp::min(32, decrypted_proof.len())]));
            decrypted_proofs.push(decrypted_proof);
        }
        
        tracing::info!("=== DECRYPTION COMPLETE ===");
        debug!("Successfully decrypted {} proofs", decrypted_proofs.len());
        Ok(decrypted_proofs)
    }

    async fn take_background_join_handle(&self) -> Option<JoinHandle<()>> {
        self.inner().take_background_join_handle().await
    }

    async fn get_signer(&self) -> <Self::Spec as DaSpec>::Address {
        self.inner().get_signer().await
    }
}

