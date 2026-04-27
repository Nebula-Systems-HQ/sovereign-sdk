use sov_blob_sender::BlobExecutionStatus;
use sov_blob_sender::{BlobInternalId, BlobSender, BlobToSend};
use sov_blob_storage::{
    EncryptedPreferredBatchData, PreferredBatchData, PreferredProofData,
    ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
};
use sov_db::ledger_db::LedgerDb;
use sov_encryption::EncryptionLayer;
use sov_modules_api::TxHash;
use sov_rollup_interface::node::da::DaService;
use std::{
    path::Path,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::sync::broadcast;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::debug;

use super::db::{ReadBatch, ReadBlob};
use crate::preferred::db::SequencerRole;
use crate::{common::TxStatusBlobSenderHooks, TxStatusManager};

/// Wrapper around [`BlobSender`] with preferred blob -specific logic.
pub struct PreferredBlobSender<Da: DaService> {
    inner: Option<BlobSender<Da, TxStatusBlobSenderHooks<Da::Spec>, LedgerDb>>,
    nb_of_concurrent_blob_submissions: Arc<AtomicUsize>,
    encryption_layer: Option<EncryptionLayer>,
}

impl<Da: DaService> PreferredBlobSender<Da> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        da: Da,
        ledger_db: LedgerDb,
        all_completed_blobs: Vec<ReadBlob>,
        storage_path: Box<Path>,
        tx_status_manager: TxStatusManager<Da::Spec>,
        shutdown_sender: watch::Sender<()>,
        blob_processing_timeout: Duration,
        blobs_sender_channel: broadcast::Sender<BlobExecutionStatus<Da::Spec>>,
        seq_role: SequencerRole,
        shared_encryption_layer: Option<EncryptionLayer>,
    ) -> anyhow::Result<(Self, Option<JoinHandle<()>>)> {
        let nb_of_concurrent_blob_submissions = Arc::new(AtomicUsize::new(0));
        match seq_role {
            SequencerRole::PgSyncReplica | SequencerRole::DaOnlyReplica => Ok((
                Self {
                    inner: None,
                    nb_of_concurrent_blob_submissions,
                    encryption_layer: shared_encryption_layer,
                },
                None,
            )),
            SequencerRole::BatchProducer => {
                // It's possible that sov-blob-sender's DB might miss some blob data at
                // node startup due to:
                //  1. Disk failure (the sequencer can use Postgres so it's durable).
                //  2. DB corruption.
                //  3. Node crash at an inconvenient time.
                // Let's restore all missing blob data to make sure they land on the DA.
                let blobs_to_send =
                    create_blobs_to_send(all_completed_blobs, shared_encryption_layer.as_ref())?;
                let (inner, blob_sender_handle) = BlobSender::new(
                    da.clone(),
                    ledger_db,
                    storage_path.as_ref(),
                    TxStatusBlobSenderHooks::new(tx_status_manager.clone()),
                    shutdown_sender,
                    blob_processing_timeout,
                    Some(blobs_sender_channel),
                    blobs_to_send,
                    nb_of_concurrent_blob_submissions.clone(),
                )
                .await?;

                Ok((
                    Self {
                        inner: Some(inner),
                        nb_of_concurrent_blob_submissions,
                        encryption_layer: shared_encryption_layer,
                    },
                    Some(blob_sender_handle),
                ))
            }
        }
    }

    pub(crate) async fn publish_proof(
        &mut self,
        proof_data: Arc<[u8]>,
        sequence_number: u64,
        blob_id: BlobInternalId,
    ) -> anyhow::Result<()> {
        let Some(ref mut inner) = self.inner else {
            return Ok(());
        };

        let blob_bytes = proof_bytes(&proof_data, sequence_number)?;

        debug!(
            sequence_number,
            blob_id, "Dispatching proof blob for publishing"
        );

        inner.publish_proof_blob(blob_bytes, blob_id).await?;

        Ok(())
    }

    pub(crate) async fn publish_batch(&mut self, batch: ReadBatch) -> anyhow::Result<()> {
        let Some(ref mut inner) = self.inner else {
            return Ok(());
        };

        let blob_id = batch.blob_id;
        let data = batch_bytes(batch, self.encryption_layer.as_ref())?;

        inner.publish_batch_blob(data, blob_id).await?;

        Ok(())
    }

    pub async fn publish_blobs_for_recovery(
        &mut self,
        completed_blobs: Vec<ReadBlob>,
    ) -> anyhow::Result<()> {
        for blob in completed_blobs {
            match blob {
                ReadBlob::Batch(batch) => {
                    self.publish_batch(batch).await?;
                }
                ReadBlob::Proof {
                    data,
                    sequence_number,
                    blob_id,
                } => {
                    self.publish_proof(data, sequence_number, blob_id).await?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn nb_of_in_flight_blobs(&self) -> Arc<AtomicUsize> {
        self.nb_of_concurrent_blob_submissions.clone()
    }

    pub(crate) async fn add_txs(&self, blob_id: BlobInternalId, tx_hashes: Arc<Vec<TxHash>>) {
        let Some(ref inner) = self.inner else {
            return;
        };

        inner.hooks().add_txs(blob_id, tx_hashes).await;
    }
}

pub fn create_blobs_to_send(
    completed_blobs: Vec<ReadBlob>,
    encryption_layer: Option<&EncryptionLayer>,
) -> anyhow::Result<Vec<(BlobToSend, BlobInternalId)>> {
    let mut blobs_to_send = Vec::new();

    for blob in completed_blobs {
        match blob {
            ReadBlob::Batch(batch) => {
                let blob_id = batch.blob_id;
                let data = batch_bytes(batch, encryption_layer)?;
                blobs_to_send.push((BlobToSend::Batch { data }, blob_id));
            }
            ReadBlob::Proof {
                data,
                sequence_number,
                blob_id,
            } => {
                let data = proof_bytes(&data, sequence_number)?;
                debug!(
                    sequence_number,
                    blob_id, "Dispatching proof blob for publishing"
                );

                blobs_to_send.push((BlobToSend::Proof { data }, blob_id));
            }
        }
    }

    Ok(blobs_to_send)
}

fn proof_bytes(proof_data: &[u8], sequence_number: u64) -> anyhow::Result<Arc<[u8]>> {
    let blob = PreferredProofData {
        sequence_number,
        data: proof_data.to_vec(),
    };
    Ok(Arc::from(borsh::to_vec(&blob)?))
}

fn batch_bytes(
    batch: ReadBatch,
    encryption_layer: Option<&EncryptionLayer>,
) -> anyhow::Result<Arc<[u8]>> {
    if let Some(encryptor) = encryption_layer {
        let txs_serialized = borsh::to_vec(&*batch.txs)?;
        let encrypted_txs_data = encryptor.encrypt(&txs_serialized)?;

        Ok(
            borsh::to_vec::<EncryptedPreferredBatchData>(&EncryptedPreferredBatchData {
                encryption_format_version: ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
                sequence_number: batch.sequence_number,
                visible_slots_to_advance: batch.visible_slots_to_advance,
                encrypted_txs_data,
            })?
            .into(),
        )
    } else {
        Ok(borsh::to_vec::<PreferredBatchData>(&PreferredBatchData {
            sequence_number: batch.sequence_number,
            visible_slots_to_advance: batch.visible_slots_to_advance,
            data: batch.txs,
        })?
        .into())
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZero, sync::Arc};

    use borsh::BorshDeserialize;
    use sov_blob_sender::new_blob_id;
    use sov_blob_storage::{
        EncryptedPreferredBatchData, PreferredBatchData, ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
    };
    use sov_encryption::{BatchEncryptionConfig, EncryptionLayer};
    use sov_modules_api::{FullyBakedTx, TxHash, VisibleSlotNumber};

    use super::{batch_bytes, ReadBatch};

    fn encryption_layer() -> EncryptionLayer {
        EncryptionLayer::from_config(BatchEncryptionConfig::Static {
            encryption_key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        })
        .unwrap()
    }

    fn read_batch() -> ReadBatch {
        ReadBatch {
            sequence_number: 7,
            visible_slot_number_after_increase: VisibleSlotNumber::new_dangerous(10),
            visible_slots_to_advance: NonZero::new(1).unwrap(),
            blob_id: new_blob_id(),
            txs: Arc::new(vec![
                FullyBakedTx::new(vec![1, 2, 3]),
                FullyBakedTx::new(vec![4, 5]),
            ]),
            tx_hashes: Arc::new(vec![TxHash::new([1; 32]), TxHash::new([2; 32])]),
        }
    }

    #[test]
    fn unencrypted_batch_bytes_decode_as_preferred_batch() {
        let bytes = batch_bytes(read_batch(), None).unwrap();
        let batch = PreferredBatchData::try_from_slice(&bytes).unwrap();
        assert_eq!(batch.sequence_number, 7);
        assert_eq!(batch.data.len(), 2);
    }

    #[test]
    fn encrypted_batch_bytes_hide_plaintext_and_round_trip() {
        let layer = encryption_layer();
        let batch = read_batch();
        let plaintext_txs = borsh::to_vec(&*batch.txs).unwrap();
        let tx_hashes = batch.tx_hashes.clone();
        let bytes = batch_bytes(batch, Some(&layer)).unwrap();

        assert!(
            !bytes
                .windows(plaintext_txs.len())
                .any(|window| window == plaintext_txs.as_slice()),
            "encrypted blob must not contain serialized plaintext transactions"
        );
        for tx_hash in tx_hashes.iter() {
            assert!(
                !bytes
                    .windows(tx_hash.0.len())
                    .any(|window| window == tx_hash.0.as_slice()),
                "encrypted blob must not contain visible transaction hashes"
            );
        }

        let encrypted = EncryptedPreferredBatchData::try_from_slice(&bytes).unwrap();
        assert_eq!(encrypted.sequence_number, 7);
        assert_eq!(
            encrypted.encryption_format_version,
            ENCRYPTED_PREFERRED_BATCH_DATA_VERSION
        );
        let decrypted = layer.decrypt(&encrypted.encrypted_txs_data).unwrap();
        let txs = Vec::<FullyBakedTx>::try_from_slice(&decrypted).unwrap();
        assert_eq!(txs.len(), 2);
    }
}
