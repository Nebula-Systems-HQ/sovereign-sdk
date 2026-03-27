use sov_modules_api::macros::serialize;
use sov_modules_api::{Amount, Spec};

use crate::utils::TokenHolder;
use crate::{Coins, TokenId};

/// Bank Event
#[derive(Debug, PartialEq, Clone, schemars::JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(bound = "S: Spec", rename_all = "snake_case")]
#[schemars(bound = "S: Spec", rename = "Event")]
pub enum Event<S: Spec> {
    /// Event for Token Creation
    TokenCreated {
        /// The name of the new token.
        token_name: String,
        /// The new tokens that were minted.
        coins: Coins,
        /// The token holder that the new tokens are minted to.
        mint_to_address: TokenHolder<S>,
        /// The token holder that submitted the minting transaction.
        minter: TokenHolder<S>,
        /// The supply cap of the token.
        supply_cap: Amount,
        /// Admin list.
        admins: Vec<TokenHolder<S>>,
    },
    /// Event for Token Transfer
    TokenTransferred {
        /// The identity that is transferring the tokens.
        from: TokenHolder<S>,
        /// The token holder that the tokens were transferred to.
        to: TokenHolder<S>,
        /// The tokens transferred.
        coins: Coins,
        /// The message included with the transfer
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memo: Option<String>,
    },
    /// Some tokens were burned
    TokenBurned {
        /// The owner that burnt the tokens.
        owner: TokenHolder<S>,
        /// The tokens that were burned.
        coins: Coins,
    },
    /// The supply of a token was frozen
    TokenFrozen {
        /// The token holder that froze the tokens
        freezer: TokenHolder<S>,
        /// The ID of the token that was transferred
        token_id: TokenId,
    },
    /// Event for Token Minting
    TokenMinted {
        /// The identity that authorized the tokens to be minted
        authorizer: TokenHolder<S>,
        /// The identity to mint the tokens to
        mint_to_identity: TokenHolder<S>,
        /// The coins minted
        coins: Coins,
    },
    /// Diagnostic event emitted after gas payer layer settlement.
    /// Contains the net gas cost and gas metering details.
    GasCharged {
        /// The address that paid for gas
        gas_payer: TokenHolder<S>,
        /// The sequencer that received the gas payment
        sequencer: TokenHolder<S>,
        /// The net amount of gas tokens charged (actual_cost = dot(gas_consumed, gas_price))
        net_amount: Amount,
        /// Gas units consumed during execution
        gas_consumed: [u64; 2],
        /// Gas price per dimension
        gas_price: [u128; 2],
    },
}
