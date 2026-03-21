//! Gas billing trait for gas payer layer settlement.
//!
//! This module defines the [`GasBiller`] trait which provides an interface for
//! gas billing operations. This trait is implemented by the Bank module to enable
//! gas payer layer billing in [`LayeredRevertableTxState`].

use sov_state::EventContainer;

use crate::{Amount, Spec, StateAccessor};

/// Error type for gas billing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasBillingError {
    /// State access error during billing.
    StateAccessError(String),
    /// Token transfer error during billing.
    TransferError(String),
}

impl std::fmt::Display for GasBillingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateAccessError(msg) => write!(f, "State access error: {}", msg),
            Self::TransferError(msg) => write!(f, "Transfer error: {}", msg),
        }
    }
}

impl std::error::Error for GasBillingError {}

/// Trait for gas billing operations, implemented by Bank.
///
/// Used by [`LayeredRevertableTxState`] to switch gas payer context in nested
/// calls - the inner call's gas is charged to the callee, not the original caller.
pub trait GasBiller<S: Spec> {
    /// Get the gas token balance of an address.
    ///
    /// # Arguments
    /// * `address` - The address to query the balance for.
    /// * `state` - State accessor for reading balance.
    ///
    /// # Returns
    /// The gas token balance, or `None` if the account doesn't exist.
    fn gas_balance_of(
        &self,
        address: &S::Address,
        state: &mut impl StateAccessor,
    ) -> Result<Option<Amount>, GasBillingError>;

    /// Transfer gas tokens from one address to another.
    ///
    /// This is used to bill gas payers when settling a gas payer layer.
    /// The transfer is performed directly to ensure gas payments are permanent
    /// and not affected by layer reverts.
    ///
    /// # Arguments
    /// * `from` - The address to transfer from (gas payer).
    /// * `to` - The address to transfer to (typically sequencer/operator).
    /// * `amount` - The amount of gas tokens to transfer.
    /// * `state` - State accessor for performing the transfer.
    fn transfer_gas_tokens(
        &mut self,
        from: &S::Address,
        to: &S::Address,
        amount: Amount,
        state: &mut (impl StateAccessor + EventContainer),
    ) -> Result<(), GasBillingError>;
}
