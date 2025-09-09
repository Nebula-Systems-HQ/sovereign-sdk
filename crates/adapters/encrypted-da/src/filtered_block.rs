use std::sync::Arc;

use sov_encryption::EncryptionLayerTrait;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::node::da::SlotData;

/// A wrapper around the inner FilteredBlock for encrypted DA
/// 
/// This implementation uses lazy decryption - blobs are decrypted only when
/// they are extracted via extract_relevant_blobs().
pub struct EncryptedFilteredBlock<T>
where
    T: SlotData,
{
    inner: T,
    encryption: Arc<Box<dyn EncryptionLayerTrait>>,
}

// Manual implementation of required traits since we can't derive them for trait objects
impl<T> Clone for EncryptedFilteredBlock<T>
where
    T: SlotData + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            encryption: self.encryption.clone(),
        }
    }
}

impl<T> std::fmt::Debug for EncryptedFilteredBlock<T>
where
    T: SlotData + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFilteredBlock")
            .field("inner", &self.inner)
            .field("encryption", &format!("{:?}", &*self.encryption))
            .finish()
    }
}

impl<T> PartialEq for EncryptedFilteredBlock<T>
where
    T: SlotData + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        // Note: We only compare the inner block, not the encryption layer
        // since the encryption layer contains function pointers that can't be compared
        self.inner == other.inner
    }
}

// For SlotData requirements, we need Serialize and Deserialize
// We only serialize the inner block - encryption layer can't be serialized
impl<T> serde::Serialize for EncryptedFilteredBlock<T>
where
    T: SlotData + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Only serialize the inner block - encryption layer will need to be reconstructed
        self.inner.serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for EncryptedFilteredBlock<T>
where
    T: SlotData,
    for<'a> T: serde::Deserialize<'a>,
{
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // We can't deserialize EncryptedFilteredBlock because the encryption layer
        // contains function pointers that can't be serialized/deserialized.
        // In practice, encrypted blocks should be created through the EncryptedDaService
        // and not deserialized from external sources.
        use serde::de::Error;
        Err(D::Error::custom(
            "EncryptedFilteredBlock cannot be deserialized - encryption layer contains \
            non-serializable function pointers. Create through EncryptedDaService instead."
        ))
    }
}

impl<T> EncryptedFilteredBlock<T>
where
    T: SlotData,
{
    /// Create a new encrypted filtered block wrapper
    pub async fn new(inner: T, encryption: Arc<Box<dyn EncryptionLayerTrait>>) -> Result<Self, anyhow::Error> {
        Ok(Self {
            inner,
            encryption,
        })
    }
    
    /// Get a reference to the inner block
    pub fn inner(&self) -> &T {
        &self.inner
    }
    
    /// Get a reference to the encryption layer
    pub fn encryption(&self) -> &Arc<Box<dyn EncryptionLayerTrait>> {
        &self.encryption
    }
}

impl<T> SlotData for EncryptedFilteredBlock<T>
where
    T: SlotData,
{
    type BlockHeader = T::BlockHeader;

    fn hash(&self) -> [u8; 32] {
        self.inner.hash()
    }

    fn header(&self) -> &Self::BlockHeader {
        self.inner.header()
    }

    fn timestamp(&self) -> Time {
        self.inner.timestamp()
    }
}