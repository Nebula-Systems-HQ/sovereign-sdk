pub mod config;
pub mod error;
pub mod encrypted_service;
pub mod encrypted_verifier;
pub mod da_service;
pub mod filtered_block;

pub use config::*;
pub use error::*;
pub use encrypted_service::*;
pub use encrypted_verifier::*;
pub use filtered_block::*;

#[cfg(test)]
mod tests;

// Type aliases for common DA service combinations
#[cfg(feature = "mock-da")]
/// Type alias for an encrypted mock DA service using StorableMockDaService
pub type EncryptedMockDaService = EncryptedDaService<sov_mock_da::storable::service::StorableMockDaService>;

#[cfg(feature = "mock-da")]
/// Type alias for an encrypted mock DA verifier using MockDaVerifier
pub type EncryptedMockDaVerifier = EncryptedDaVerifier<sov_mock_da::MockDaVerifier>;

// Add more type aliases as needed for other DA adapters
// #[cfg(feature = "celestia")]
// pub type EncryptedCelestiaDaService = EncryptedDaService<sov_celestia_adapter::CelestiaService>;
// pub type EncryptedCelestiaDaVerifier = EncryptedDaVerifier<sov_celestia_adapter::CelestiaVerifier>;