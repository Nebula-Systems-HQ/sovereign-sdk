use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BatchEncryptionConfig {
    /// Static key configuration. The key is a hex-encoded 32-byte AES-256-GCM key.
    Static {
        /// Hex-encoded AES-256-GCM encryption key.
        encryption_key: String,
    },
}

impl std::fmt::Debug for BatchEncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchEncryptionConfig::Static { .. } => f
                .debug_struct("Static")
                .field("encryption_key", &"[REDACTED]")
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_static_key_material() {
        let encryption_key = (1u8..=32).map(|b| format!("{b:02x}")).collect::<String>();
        let config = BatchEncryptionConfig::Static {
            encryption_key: encryption_key.clone(),
        };

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&encryption_key));
    }
}
