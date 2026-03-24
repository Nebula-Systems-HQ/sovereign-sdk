//! Implementation of `GasBiller` trait for the Bank module.
//!
//! This enables the Bank to be used for gas payer layer billing in
//! [`LayeredRevertableTxState`]

use sov_modules_api::{Amount, EventEmitter, Gas, GasBiller, GasBillingError, Spec, StateAccessor};
use sov_state::EventContainer;

use crate::event::Event;
use crate::utils::TokenHolder;
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

    fn emit_net_gas_event(
        &self,
        gas_payer: &S::Address,
        sequencer: &S::Address,
        net_amount: Amount,
        gas_consumed: S::Gas,
        gas_price: <S::Gas as Gas>::Price,
        state: &mut impl EventContainer,
    ) {
        // Emit TokenTransferred for balance tracking (indexers/clients)
        self.emit_event(
            state,
            Event::TokenTransferred {
                from: TokenHolder::User(*gas_payer),
                to: TokenHolder::User(*sequencer),
                coins: Coins {
                    amount: net_amount,
                    token_id: config_gas_token_id(),
                },
                memo: Some("gas".to_string()),
            },
        );

        // Emit GasCharged for diagnostics
        let gas_consumed_arr: [u64; 2] = gas_consumed.into();
        let gas_price_arr: [Amount; 2] = gas_price.into();
        self.emit_event(
            state,
            Event::GasCharged {
                gas_payer: TokenHolder::User(*gas_payer),
                sequencer: TokenHolder::User(*sequencer),
                net_amount,
                gas_consumed: gas_consumed_arr,
                gas_price: [gas_price_arr[0].0, gas_price_arr[1].0],
            },
        );
    }
}
