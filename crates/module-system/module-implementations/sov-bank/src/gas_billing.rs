//! Implementation of `GasBiller` trait for the Bank module.
//!
//! This enables the Bank to be used for gas payer layer billing in
//! [`LayeredRevertableTxState`]

use sov_modules_api::{Amount, GasBiller, GasBillingError, Spec, StateAccessor};

use crate::{config_gas_token_id, Bank, Coins};

impl<S: Spec> GasBiller<S> for Bank<S> {
    fn gas_balance_of(
        &self,
        address: &S::Address,
        state: &mut impl StateAccessor,
    ) -> Result<Option<Amount>, GasBillingError> {
        self.get_balance_of(address, config_gas_token_id(), state)
            .map_err(|e| GasBillingError::StateAccessError(e.to_string()))
    }

    fn transfer_gas_tokens(
        &mut self,
        from: &S::Address,
        to: &S::Address,
        amount: Amount,
        state: &mut impl StateAccessor,
    ) -> Result<(), GasBillingError> {
        self.transfer_from(
            from,
            to,
            Coins {
                amount,
                token_id: config_gas_token_id(),
            },
            state,
        )
        .map_err(|e| GasBillingError::TransferError(e.to_string()))
    }
}
