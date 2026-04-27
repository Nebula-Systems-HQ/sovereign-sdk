//! Gas billing trait for gas payer layer settlement.
//!
//! This module defines the [`GasBiller`] trait which provides an interface for
//! gas billing operations. This trait is implemented by the Bank module to enable
//! gas payer layer billing in [`LayeredRevertableTxState`].

use sov_state::EventContainer;

use crate::{Amount, Gas, Spec, StateAccessor};

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

    /// Transfer gas tokens from one address to another (silent, no events).
    ///
    /// This is used internally by gas payer layers for upfront charge and refund.
    /// No events are emitted — use [`emit_net_gas_event`] after settlement to emit
    /// a single consolidated event for the net gas cost.
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
        state: &mut impl StateAccessor,
    ) -> Result<(), GasBillingError>;

    /// Emit a consolidated gas event after gas payer layer settlement.
    ///
    /// Called once after the upfront charge + refund cycle to emit a single
    /// `TokenTransferred` event (for balance tracking) and a `GasCharged` event
    /// (for diagnostics) with the net gas cost.
    fn emit_net_gas_event(
        &self,
        gas_payer: &S::Address,
        sequencer: &S::Address,
        net_amount: Amount,
        gas_consumed: S::Gas,
        gas_price: <S::Gas as Gas>::Price,
        state: &mut impl EventContainer,
    );
}
