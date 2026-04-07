use std::collections::HashMap;
use std::num::NonZeroU64;

use sov_metrics::{AuthAndProcessMetrics, AuthAndProcessTimings};
use sov_modules_api::capabilities::{
    GasEnforcer, HasCapabilities, HasKernel, TransactionAuthenticator,
};
use sov_modules_api::hooks::{BlockHooks, FinalizeHook, TxHooks};
use sov_modules_api::macros::config_value;
use sov_modules_api::transaction::{AuthenticatedTransactionData, Credentials, TxDetails};
use sov_modules_api::{
    Amount, BasicGasMeter, Context, DispatchCall, ExecutionContext, FullyBakedTx, Gas, GasMeter,
    GasSpec, Genesis, ModuleInfo, NestedEnumUtils, NoOpControlFlow, OperatingMode, Runtime,
    RuntimeEventProcessor, SequencerType, Spec, StateCheckpoint, StateProvider, StateReader,
    TxEffect, TxProcessingError, TxState, WorkingSet,
};
use sov_modules_stf_blueprint::process_tx_and_reward_prover;
use sov_paymaster::{
    AllowedSequencerUpdate, CallMessage as PaymasterCallMessage, Event as PaymasterEvent,
    PayeePolicy, Paymaster, PaymasterPolicyInitializer, PolicyUpdate, SafeVec,
};
use sov_test_utils::runtime::{TestRunner, TokenId, ValueSetter, ValueSetterCallMessage};
use sov_test_utils::storage::ForklessStorageManager;
use sov_test_utils::{
    default_test_tx_details, AsUser, EncodeCall, TransactionTestCase, TransactionType,
    TEST_DEFAULT_MAX_FEE, TEST_DEFAULT_MAX_PRIORITY_FEE, TEST_DEFAULT_USER_BALANCE,
};

use crate::runtime::{PaymasterRuntime, PaymasterRuntimeEvent};
use crate::utils::{setup, DoValueSetterTx, TxOutcome, RT, S};

// This module implements the following tests for the paymaster
// -[x] Register paymaster using call message
// -[x] Set payer for sequencer using call message
// -[x] Register payee for user
// -[x] Update payee policy for a user
// -[x] Remove payee policy for a user
// -[x] Remove payer for sequencer
// -[x] Update authorized sequencers
// -[x] Update authorized updaters
// -[x] Update default payee policy
// -[x] Test happy path - paymaster pays with default policy
// -[x] Test happy path - paymaster pays with special policy
// -[x] Test unhappy path - paymaster does not have enough balance
// -[x] Test unhappy path - paymaster is not registered
// -[] Test unhappy path - paymaster is not authorized to pay for sequencer
// -[x] Test unhappy path - paymaster is not authorized to pay for user
//   -[x] Gas price too high
//   -[x] Gas limit too high
//   -[x] Max fee too high
//   -[x] Denied
// -[x] Test unhappy path - user pays when paymaster does not. In this case, paymaster balance must be unchanged

#[derive(Clone, Default)]
struct FailingPreReserveRuntime<S: Spec> {
    inner: PaymasterRuntime<S>,
}

impl<S: Spec> DispatchCall for FailingPreReserveRuntime<S> {
    type Spec = S;
    type Decodable = <PaymasterRuntime<S> as DispatchCall>::Decodable;

    fn encode(decodable: &Self::Decodable) -> Vec<u8> {
        <PaymasterRuntime<S> as DispatchCall>::encode(decodable)
    }

    fn dispatch_call<I: StateProvider<Self::Spec>>(
        &mut self,
        message: Self::Decodable,
        state: &mut WorkingSet<Self::Spec, I>,
        context: &Context<Self::Spec>,
    ) -> Result<(), sov_modules_api::Error> {
        self.inner.dispatch_call(message, state, context)
    }

    fn module_id(&self, message: &Self::Decodable) -> &sov_modules_api::ModuleId {
        self.inner.module_id(message)
    }

    fn module_info(
        &self,
        discriminant: <Self::Decodable as NestedEnumUtils>::Discriminants,
    ) -> &dyn ModuleInfo<Spec = Self::Spec> {
        self.inner.module_info(discriminant)
    }
}

impl<S: Spec> RuntimeEventProcessor for FailingPreReserveRuntime<S> {
    type RuntimeEvent = <PaymasterRuntime<S> as RuntimeEventProcessor>::RuntimeEvent;

    fn convert_to_runtime_event(
        event: sov_modules_api::TypeErasedEvent,
    ) -> Option<Self::RuntimeEvent> {
        <PaymasterRuntime<S> as RuntimeEventProcessor>::convert_to_runtime_event(event)
    }
}

impl<S: Spec> HasCapabilities<S> for FailingPreReserveRuntime<S> {
    type Capabilities<'a>
        = <PaymasterRuntime<S> as HasCapabilities<S>>::Capabilities<'a>
    where
        Self: 'a;

    fn capabilities(&mut self) -> sov_modules_api::capabilities::Guard<Self::Capabilities<'_>> {
        self.inner.capabilities()
    }
}

impl<S: Spec> HasKernel<S> for FailingPreReserveRuntime<S> {
    type Kernel<'a>
        = <PaymasterRuntime<S> as HasKernel<S>>::Kernel<'a>
    where
        Self: 'a;

    fn inner(&mut self) -> sov_modules_api::capabilities::Guard<Self::Kernel<'_>> {
        <PaymasterRuntime<S> as HasKernel<S>>::inner(&mut self.inner)
    }

    fn kernel_with_slot_mapping(
        &self,
    ) -> std::sync::Arc<dyn sov_modules_api::capabilities::KernelWithSlotMapping<S>> {
        self.inner.kernel_with_slot_mapping()
    }
}

impl<S: Spec> Genesis for FailingPreReserveRuntime<S> {
    type Spec = S;
    type Config = <PaymasterRuntime<S> as Genesis>::Config;

    fn genesis(
        &mut self,
        genesis_rollup_header: &<<Self::Spec as Spec>::Da as sov_modules_api::DaSpec>::BlockHeader,
        config: &Self::Config,
        state: &mut impl sov_modules_api::GenesisState<Self::Spec>,
    ) -> Result<(), sov_modules_api::Error> {
        self.inner.genesis(genesis_rollup_header, config, state)
    }
}

impl<S: Spec> TxHooks for FailingPreReserveRuntime<S> {
    type Spec = S;

    fn pre_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        tx: &AuthenticatedTransactionData<Self::Spec>,
        state: &mut T,
    ) -> anyhow::Result<()> {
        <PaymasterRuntime<S> as TxHooks>::pre_dispatch_tx_hook(&mut self.inner, tx, state)
    }

    fn post_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        tx: &AuthenticatedTransactionData<Self::Spec>,
        ctx: &Context<Self::Spec>,
        state: &mut T,
    ) -> anyhow::Result<()> {
        <PaymasterRuntime<S> as TxHooks>::post_dispatch_tx_hook(&mut self.inner, tx, ctx, state)
    }
}

impl<S: Spec> BlockHooks for FailingPreReserveRuntime<S> {
    type Spec = S;

    fn begin_rollup_block_hook(
        &mut self,
        visible_hash: &<<Self::Spec as Spec>::Storage as sov_modules_api::Storage>::Root,
        state: &mut StateCheckpoint<Self::Spec>,
    ) {
        <PaymasterRuntime<S> as BlockHooks>::begin_rollup_block_hook(
            &mut self.inner,
            visible_hash,
            state,
        );
    }

    fn end_rollup_block_hook(&mut self, state: &mut StateCheckpoint<Self::Spec>) {
        <PaymasterRuntime<S> as BlockHooks>::end_rollup_block_hook(&mut self.inner, state);
    }
}

impl<S: Spec> FinalizeHook for FailingPreReserveRuntime<S> {
    type Spec = S;

    fn finalize_hook(
        &mut self,
        root_hash: &<<Self::Spec as Spec>::Storage as sov_modules_api::Storage>::Root,
        state: &mut impl sov_modules_api::AccessoryStateReaderAndWriter,
    ) {
        <PaymasterRuntime<S> as FinalizeHook>::finalize_hook(&mut self.inner, root_hash, state);
    }
}

impl<S> Runtime<S> for FailingPreReserveRuntime<S>
where
    S: Spec,
    sov_modules_api::transaction::Transaction<Self, S>:
        sov_modules_api::sov_universal_wallet::schema::UniversalWallet,
    <Self as DispatchCall>::Decodable:
        sov_modules_api::sov_universal_wallet::schema::UniversalWallet,
{
    const CHAIN_HASH: [u8; 32] = <PaymasterRuntime<S> as Runtime<S>>::CHAIN_HASH;

    type GenesisConfig = <PaymasterRuntime<S> as Runtime<S>>::GenesisConfig;
    type GenesisInput = <PaymasterRuntime<S> as Runtime<S>>::GenesisInput;
    type ModuleExecutionConfig = <PaymasterRuntime<S> as Runtime<S>>::ModuleExecutionConfig;
    type Auth = <PaymasterRuntime<S> as Runtime<S>>::Auth;

    fn endpoints(api_state: sov_modules_api::rest::ApiState<S>) -> sov_modules_api::NodeEndpoints {
        <PaymasterRuntime<S> as Runtime<S>>::endpoints(api_state)
    }

    fn genesis_config(input: &Self::GenesisInput) -> anyhow::Result<Self::GenesisConfig> {
        <PaymasterRuntime<S> as Runtime<S>>::genesis_config(input)
    }

    fn operating_mode(genesis: &Self::GenesisConfig) -> OperatingMode {
        <PaymasterRuntime<S> as Runtime<S>>::operating_mode(genesis)
    }

    fn wrap_call(
        auth_data: <Self::Auth as TransactionAuthenticator<S>>::Decodable,
    ) -> Self::Decodable {
        <PaymasterRuntime<S> as Runtime<S>>::wrap_call(auth_data)
    }

    fn get_transaction_delay_ms(&self, call: &Self::Decodable) -> u64 {
        <PaymasterRuntime<S> as Runtime<S>>::get_transaction_delay_ms(&self.inner, call)
    }

    fn get_transaction_priority(&self, call: &FullyBakedTx) -> u32 {
        <PaymasterRuntime<S> as Runtime<S>>::get_transaction_priority(&self.inner, call)
    }

    fn pre_reserve_gas(
        &mut self,
        _call: &Self::Decodable,
        _context: &mut Context<S>,
        state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        self.inner.value_setter.value.set(&777, state)?;
        Err(anyhow::anyhow!("delegated billing denied"))
    }

    fn is_unauthorized_system_tx(
        &self,
        call: &Self::Decodable,
        context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> bool {
        <PaymasterRuntime<S> as Runtime<S>>::is_unauthorized_system_tx(
            &self.inner,
            call,
            context,
            state,
        )
    }

    fn populate_pinned_cache(storage: &S::Storage) -> Option<sov_state::pinned_cache::PinnedCache> {
        <PaymasterRuntime<S> as Runtime<S>>::populate_pinned_cache(storage)
    }

    fn resolve_address<ST: StateReader<sov_modules_api::User>>(
        &self,
        default_address: &S::Address,
        credential_id: &sov_modules_api::CredentialId,
        state: &mut ST,
    ) -> Result<S::Address, ST::Error> {
        <PaymasterRuntime<S> as Runtime<S>>::resolve_address(
            &self.inner,
            default_address,
            credential_id,
            state,
        )
    }

    fn on_gas_charged(
        &self,
        state: &mut impl sov_state::EventContainer,
        gas_payer: &S::Address,
        sequencer: &S::Address,
        amount: Amount,
    ) {
        <PaymasterRuntime<S> as Runtime<S>>::on_gas_charged(
            &self.inner,
            state,
            gas_payer,
            sequencer,
            amount,
        );
    }
}

// Test that a transaction for a user succeeds even when the user has no balance to pay for gas
// if the paymaster is willing to cover that user.
#[test]
fn test_basic() {
    let setup = setup(Amount::ZERO);
    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Run a basic tx to check the setup
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
}

// Test that a policy can be updated and its outcome changes accordingly for the user
#[test]
fn test_basic_policy_update() {
    let setup = setup(Amount::ZERO);
    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Run a basic tx to check the setup
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);

    // Now change the policy of the payer to deny the user
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: setup.payer.address(),
                update: PolicyUpdate::default().set_default_policy(PayeePolicy::Deny),
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
        }),
    });

    // Check that the next user transaction is not executed
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);
}

// Register a payer using a call message and check that it works
#[test]
fn test_registering_new_payer() {
    let mut setup = setup(Amount::ZERO);
    // Don't configure a payer at genesis.
    setup.genesis_config.paymaster.payers.truncate(0);

    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Check that the user transaction fails without a paymaster
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

    // Register a payer and assert success
    let payer_address = setup.payer.address();
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::RegisterPaymaster {
                policy: PaymasterPolicyInitializer {
                    default_payee_policy: PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: None,
                    },
                    payees: SafeVec::new(),
                    authorized_sequencers: sov_paymaster::AuthorizedSequencers::All,
                    authorized_updaters: [setup.payer.address()].as_ref().try_into().unwrap(),
                },
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::SetPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: payer_address
                })
            );
        }),
    });

    // Retry the user transaction and check that is succeeds
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
}

// Set the payer for a sequencer using a call message
#[test]
fn test_setting_payer_for_sequencer() {
    let setup = setup(TEST_DEFAULT_USER_BALANCE);
    let mut runner = TestRunner::<_, _>::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Register the user as a new payer. This sets the user as payer for the active sequencer.
    let user_address = setup.user.address();
    let payer_address = setup.payer.address();
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::RegisterPaymaster {
                policy: PaymasterPolicyInitializer {
                    default_payee_policy: PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: None,
                    },
                    payees: SafeVec::new(),
                    authorized_sequencers: sov_paymaster::AuthorizedSequencers::All,
                    authorized_updaters: [setup.user.address()].as_ref().try_into().unwrap(),
                },
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::SetPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: user_address
                })
            );
        }),
    });

    // Use a call message to set the paymaster for our sequencer back to the original value and check that
    // the payer address is as expected.
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::SetPayerForSequencer {
                payer: payer_address,
            },
        ),
        assert: Box::new(move |result, state| {
            assert!(result.tx_receipt.is_successful());
            let payer_for_sequencer = Paymaster::<S>::default()
                .sequencer_to_payer
                .get(&setup.sequencer.da_address, state)
                .unwrap();
            assert_eq!(payer_for_sequencer, Some(payer_address));
        }),
    });
}

// Test registering an exception to allow a specific payee to transact when most cannot.
#[test]
fn test_registering_payee() {
    let mut setup = setup(Amount::ZERO);
    setup.payer_setup().policy.default_payee_policy = PayeePolicy::Deny;

    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Check that the user transaction fails because the policy disallows it.
    // Retry the user transaction and check that it succeeds
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

    // Add a special allow policy for one payee
    {
        let payer_address = setup.payer.address();
        let user_address = setup.user.address();
        let update = PolicyUpdate::default().add_payee_policy(
            setup.user.address(),
            PayeePolicy::Allow {
                max_fee: None,
                gas_limit: None,
                max_gas_price: None,
                transaction_limit: None,
            },
        );
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: payer_address,
                    update,
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
                assert_eq!(
                    result.events.last().unwrap(),
                    &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::AddedPayeePolicy {
                        payer: payer_address,
                        payee: user_address,
                        policy: PayeePolicy::Allow {
                            max_fee: None,
                            gas_limit: None,
                            max_gas_price: None,
                            transaction_limit: None,
                        },
                    })
                );
            }),
        });
    }

    // Retry the user transaction and check that is succeeds
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);

    // Ensure that txs for other users still fail
    runner.do_value_setter_tx(&setup.user_2, TxOutcome::Skipped);
}

// Test registering a specific policy to block a particular payee when others can transact
#[test]
fn test_blocking_and_unblocking_payee() {
    let setup = setup(Amount::ZERO);
    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Check that the user transaction succeeds (because all users are allowed by default)
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);

    // Register a special policy blocking one payee
    let payer_address = setup.payer.address();
    let user_address = setup.user.address();
    let update = PolicyUpdate::default().add_payee_policy(setup.user.address(), PayeePolicy::Deny);
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: payer_address,
                update,
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::AddedPayeePolicy {
                    payer: payer_address,
                    payee: user_address,
                    policy: PayeePolicy::Deny,
                })
            );
        }),
    });

    // Try another transaction from the blocked user and ensure that it fails
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

    // Ensure that other user txs still execute
    runner.do_value_setter_tx(&setup.user_2, TxOutcome::Executed);

    // Remove the special user policy
    let update = PolicyUpdate::default().remove_payee_policy(setup.user.address());
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: payer_address,
                update,
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::RemovedPayeePolicy {
                    payer: payer_address,
                    payee: user_address
                })
            );
        }),
    });

    // Retry the user transaction and check that it works
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
}

// Test unregistering the sequencer from its paymaster
#[test]
fn test_unregistering_sequencer() {
    let setup = setup(Amount::ZERO);

    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );
    // Ensure that a user transaction succeeds
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);

    // Update the policy to block the sequencer
    let payer_address = setup.payer.address();
    let update = PolicyUpdate::default()
        .update_allowed_sequencers(AllowedSequencerUpdate::remove(setup.sequencer.da_address));
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: payer_address,
                update,
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::RemovedPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: payer_address
                })
            );
        }),
    });

    // Ensure that user txs are not paid for
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

    // Try to re-register the sequencer again. It should fail, since the sequencer isn't allowed
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::SetPayerForSequencer {
                payer: payer_address,
            },
        ),
        assert: Box::new(move |result, _state| {
            if let TxEffect::Reverted(reverted) = result.tx_receipt {
                let reason = reverted.reason.to_string();
                assert!(reason.contains("is not authorized to use paymaster"));
            } else {
                panic!("Transaction should have reverted")
            };
        }),
    });
    // Ensure that user txs are still not paid for
    runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

    // Now allow the sequencer again. Check that it was added back.
    let update = PolicyUpdate::default()
        .update_allowed_sequencers(AllowedSequencerUpdate::add(setup.sequencer.da_address));
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: payer_address,
                update,
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::SetPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: payer_address
                })
            );
        }),
    });
    // Ensure that other user txs execute again
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
}

// Test the logic for authorizing updates to the payer policy
#[test]
fn test_updates_using_alternate_address() {
    let mut setup = setup(Amount::ZERO);
    let user_address = setup.user.address();
    setup
        .payer_setup()
        .policy
        .authorized_updaters
        .try_push(user_address)
        .unwrap();
    let mut runner = TestRunner::<_, _>::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Update the sequencer policy to remove our user from the updaters list.
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: setup.payer.address(),
                update: PolicyUpdate::default().remove_updater(setup.user.address()),
            },
        ),
        assert: Box::new(move |result, _state| assert!(result.tx_receipt.is_successful())),
    });

    // Have the user try to update the policy. It should fail because the user isn't authorized to update policies
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: setup.payer.address(),
                update: PolicyUpdate::default().remove_updater(setup.user.address()),
            },
        ),
        assert: Box::new(move |result, _state| {
            if let TxEffect::Reverted(reverted) = result.tx_receipt {
                let reason = reverted.reason.to_string();
                assert!(reason.contains("is not an authorized updater"));
            } else {
                panic!("Transaction should have reverted")
            };
        }),
    });

    // Update the sequencer policy to re-add our user to the updaters list.
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: setup.payer.address(),
                update: PolicyUpdate::default().add_updater(setup.user.address()),
            },
        ),
        assert: Box::new(move |result, _state| assert!(result.tx_receipt.is_successful())),
    });

    // Have the user try to update the policy. It should succeed.
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: setup.payer.address(),
                update: PolicyUpdate::default().set_default_policy(PayeePolicy::Deny),
            },
        ),
        assert: Box::new(move |result, _state| assert!(result.tx_receipt.is_successful())),
    });
}

// Test that a user can pay for their own transactions if the configured payer has insufficient funds.
#[test]
fn test_setting_payer_with_insufficient_balance() {
    // Assumption: 1 token is not enough balance to execute a transaction. If this assumption is wrong,
    // the test will fail spuriously.
    let setup = setup(Amount::new(1));
    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Register the user (with ~0 balance) as a new payer. This sets the user as payer for the active sequencer.
    let user_address = setup.user.address();
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::RegisterPaymaster {
                policy: PaymasterPolicyInitializer {
                    default_payee_policy: PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: None,
                    },
                    payees: SafeVec::new(),
                    authorized_sequencers: sov_paymaster::AuthorizedSequencers::All,
                    authorized_updaters: [setup.user.address()].as_ref().try_into().unwrap(),
                },
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::SetPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: user_address
                })
            );
        }),
    });

    // Since the payer can't afford transactions, users without balance of their own have their txs skipped.
    runner.do_value_setter_tx(&setup.user_2, TxOutcome::Skipped);

    // Users who *do* have a balance can still execute transactions
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, ValueSetter<S>>(
            ValueSetterCallMessage::SetValue {
                value: 99,
                gas: None,
            },
        ),
        assert: Box::new(move |result, state| {
            assert!(!result.tx_receipt.is_skipped());
            // Check that the payer's balance didn't change
            let user_balance = sov_bank::Bank::<S>::default()
                .get_balance_of(&user_address, config_value!("GAS_TOKEN_ID"), state)
                .unwrap();
            assert_eq!(user_balance, Some(Amount::new(1)));
        }),
    });
}

#[test]
fn test_granular_policies() {
    let mut setup = setup(Amount::ZERO);
    // Start with a high enough max fee to allow txs and ensure success
    setup.payer_setup().policy.default_payee_policy = PayeePolicy::Allow {
        max_fee: Some(Amount::from(u64::MAX)),
        gas_limit: None,
        max_gas_price: None,
        transaction_limit: None,
    };

    let mut runner = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );
    runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);

    // Next, set the max fee too low and ensure txs aren't executed
    {
        // Update the policy
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: Some(Amount::new(1)),
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: None,
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });
        // Check that a user tx is rejected
        runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);
    }

    // Next, set the gas_limit to a high value and ensure txs run as expected if they specify a gas limit
    {
        // Update the policy
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: Some([u64::MAX, u64::MAX].into()),
                        max_gas_price: None,
                        transaction_limit: None,
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });

        // Assert that the user transaction fails if it doesn't specify a gas limit, since the policy now
        // requires one.
        runner.execute_skipped_transaction(TransactionTestCase {
            input: TransactionType::Plain {
                message: <RT as EncodeCall<ValueSetter<S>>>::to_decodable(
                    ValueSetterCallMessage::SetValue {
                        value: 99,
                        gas: None,
                    },
                ),
                key: setup.user.as_user().private_key().clone(),
                details: TxDetails {
                    max_priority_fee_bips: TEST_DEFAULT_MAX_PRIORITY_FEE,
                    max_fee: TEST_DEFAULT_MAX_FEE,
                    gas_limit: None,
                    chain_id: config_value!("CHAIN_ID"),
                },
            },
            assert: Box::new(|_, _| {}),
        });

        // Assert that the user transaction succeeds if its gas limit is valid.
        runner.execute_transaction(TransactionTestCase {
            input: TransactionType::Plain {
                message: <RT as EncodeCall<ValueSetter<S>>>::to_decodable(
                    ValueSetterCallMessage::SetValue {
                        value: 99,
                        gas: None,
                    },
                ),
                key: setup.user.as_user().private_key().clone(),
                details: TxDetails {
                    max_priority_fee_bips: TEST_DEFAULT_MAX_PRIORITY_FEE,
                    max_fee: TEST_DEFAULT_MAX_FEE,
                    // This gas limit has to be high enough to cover the tx but low enough that gas_limit * gas_price
                    // is less than the payer's balance. If we adjust the gas costs of operations too much, this value may need adjustment.
                    gas_limit: Some([100_000, 100_000].into()),
                    chain_id: config_value!("CHAIN_ID"),
                },
            },
            assert: Box::new(|result, _state| {
                assert!(!result.tx_receipt.is_skipped());
            }),
        });
    }

    // Next, set the gas_limit too low and ensure txs are skipped
    {
        // Update the policy
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: Some([1, 1].into()),
                        max_gas_price: None,
                        transaction_limit: None,
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });
        // Assert that the user transaction is skipped if its gas limit is too high
        runner.execute_skipped_transaction(TransactionTestCase {
            input: TransactionType::Plain {
                message: <RT as EncodeCall<ValueSetter<S>>>::to_decodable(
                    ValueSetterCallMessage::SetValue {
                        value: 99,
                        gas: None,
                    },
                ),
                key: setup.user.as_user().private_key().clone(),
                details: TxDetails {
                    max_priority_fee_bips: TEST_DEFAULT_MAX_PRIORITY_FEE,
                    max_fee: TEST_DEFAULT_MAX_FEE,
                    gas_limit: Some([u64::MAX, u64::MAX].into()),
                    chain_id: config_value!("CHAIN_ID"),
                },
            },
            assert: Box::new(|_, _| {}),
        });
    }

    // Next, set the max_gas_price to a high value and ensure txs run as expected
    {
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: Some([Amount::MAX, Amount::MAX].into()),
                        transaction_limit: None,
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });
        runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
    }

    // Next, set the max gas price too low and ensure txs are skipped
    {
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: Some([Amount::new(1), Amount::new(1)].into()),
                        transaction_limit: None,
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });
        runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);
    }

    // Next, set a transaction limit and ensure users are denied after the limit is used up
    {
        runner.execute_transaction(TransactionTestCase {
            input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
                PaymasterCallMessage::UpdatePolicy {
                    payer: setup.payer.address(),
                    update: PolicyUpdate::default().set_default_policy(PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: Some(NonZeroU64::new(3).unwrap()),
                    }),
                },
            ),
            assert: Box::new(move |result, _state| {
                assert!(result.tx_receipt.is_successful());
            }),
        });
        // Basic test for user 1. Three transactions should be covered
        // Transaction 1.
        runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
        // Set up a high nonce for the next test. Transaction 2.
        runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
        // Check that skipped transactions do not decrement the limit
        runner.do_value_setter_tx_with_nonce(&setup.user, 1, TxOutcome::Skipped);
        // Should still have one more tx left. Transaction 3.
        runner.do_value_setter_tx(&setup.user, TxOutcome::Executed);
        // The third tx should fail due to no longer being covered
        runner.do_value_setter_tx(&setup.user, TxOutcome::Skipped);

        // Other users should be unaffected by the first user having used up his coverage
        // User 2, transactions 1 and 2
        runner.do_value_setter_tx(&setup.user_2, TxOutcome::Executed);
        runner.do_value_setter_tx(&setup.user_2, TxOutcome::Executed);
        // Check that reverted transactions still decrement the limit - should be transaction 3
        runner.do_value_setter_tx(&setup.user_2, TxOutcome::Reverted);
        // Now the second user should no longer be covered
        runner.do_value_setter_tx(&setup.user_2, TxOutcome::Skipped);
    }
}

// Test vulnerability fix: payer cannot remove sequencers that don't belong to them
#[test]
fn test_cannot_remove_sequencer_belonging_to_different_payer() {
    let setup = setup(TEST_DEFAULT_USER_BALANCE);
    let mut runner = TestRunner::<RT, S>::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Register a second payer (user) that authorizes all sequencers
    let user_address = setup.user.address();
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::RegisterPaymaster {
                policy: PaymasterPolicyInitializer {
                    default_payee_policy: PayeePolicy::Allow {
                        max_fee: None,
                        gas_limit: None,
                        max_gas_price: None,
                        transaction_limit: None,
                    },
                    payees: SafeVec::new(),
                    authorized_sequencers: sov_paymaster::AuthorizedSequencers::Some(
                        SafeVec::try_from(vec![setup.sequencer.da_address]).unwrap(),
                    ),
                    authorized_updaters: [setup.user.address()].as_ref().try_into().unwrap(),
                },
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            // This should set the user as the payer for the sequencer
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::SetPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: user_address
                })
            );
        }),
    });

    // Now the original payer tries to remove the sequencer that is now mapped to the user
    // This should fail with an appropriate error message
    let original_payer_address = setup.payer.address();
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: original_payer_address,
                update: PolicyUpdate::default().update_allowed_sequencers(
                    AllowedSequencerUpdate::remove(setup.sequencer.da_address),
                ),
            },
        ),
        assert: Box::new(move |result, _state| {
            if let TxEffect::Reverted(reverted) = result.tx_receipt {
                let reason = reverted.reason.to_string();
                assert!(reason.contains("Cannot remove sequencer"));
                assert!(reason.contains("sequencer is currently mapped to payer"));
                assert!(reason.contains(&user_address.to_string()));
            } else {
                panic!("Transaction should have reverted with proper error message")
            };
        }),
    });

    // Verify that the sequencer is still mapped to the user, not the original payer
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, ValueSetter<S>>(
            ValueSetterCallMessage::SetValue {
                value: 99,
                gas: None,
            },
        ),
        assert: Box::new(move |result, state| {
            assert!(result.tx_receipt.is_successful());
            // Verify the mapping is still correct
            let payer_for_sequencer = Paymaster::<S>::default()
                .sequencer_to_payer
                .get(&setup.sequencer.da_address, state)
                .unwrap();
            assert_eq!(payer_for_sequencer, Some(user_address));
        }),
    });
}

// Test that legitimate removal still works: payer can remove sequencer that belongs to them
#[test]
fn test_can_remove_own_sequencer() {
    let setup = setup(Amount::ZERO);
    let mut runner = TestRunner::<_, _>::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    // Capture addresses before moving into closures
    let payer_address = setup.payer.address();

    // Verify initial state: sequencer is mapped to the payer
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, ValueSetter<S>>(
            ValueSetterCallMessage::SetValue {
                value: 99,
                gas: None,
            },
        ),
        assert: Box::new(move |result, state| {
            assert!(result.tx_receipt.is_successful());
            // Verify the mapping exists
            let payer_for_sequencer = Paymaster::<S>::default()
                .sequencer_to_payer
                .get(&setup.sequencer.da_address, state)
                .unwrap();
            assert_eq!(payer_for_sequencer, Some(payer_address));
        }),
    });

    // Now the payer legitimately removes their own sequencer
    runner.execute_transaction(TransactionTestCase {
        input: setup.payer.create_plain_message::<RT, Paymaster<S>>(
            PaymasterCallMessage::UpdatePolicy {
                payer: payer_address,
                update: PolicyUpdate::default().update_allowed_sequencers(
                    AllowedSequencerUpdate::remove(setup.sequencer.da_address),
                ),
            },
        ),
        assert: Box::new(move |result, _state| {
            assert!(result.tx_receipt.is_successful());
            assert_eq!(
                result.events.last().unwrap(),
                &PaymasterRuntimeEvent::Paymaster(PaymasterEvent::RemovedPayerForSequencer {
                    sequencer: setup.sequencer.da_address,
                    payer: payer_address
                })
            );
        }),
    });

    // Verify that the sequencer is no longer mapped to any payer
    runner.execute_transaction(TransactionTestCase {
        input: setup.user.create_plain_message::<RT, ValueSetter<S>>(
            ValueSetterCallMessage::SetValue {
                value: 99,
                gas: None,
            },
        ),
        assert: Box::new(move |result, state| {
            // Transaction should be skipped since no payer is available
            assert!(result.tx_receipt.is_skipped());
            // Verify the mapping is removed
            let payer_for_sequencer = Paymaster::<S>::default()
                .sequencer_to_payer
                .get(&setup.sequencer.da_address, state)
                .unwrap();
            assert_eq!(payer_for_sequencer, None);
        }),
    });
}

#[test]
fn test_gas_payer_override_bypasses_paymaster() {
    let mut setup = setup(Amount::ZERO);
    setup.payer_setup().policy.default_payee_policy = PayeePolicy::Allow {
        max_fee: None,
        gas_limit: None,
        max_gas_price: None,
        transaction_limit: Some(NonZeroU64::new(1).unwrap()),
    };

    let runner: TestRunner<RT, S> = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    let mut runtime = PaymasterRuntime::<S>::default();
    let storage = runner.storage_manager().create_prover_storage();
    let mut checkpoint = StateCheckpoint::<S>::new(storage, &runtime.kernel(), None);

    let sender = setup.user.address();
    let payer = setup.payer.address();
    let tx = AuthenticatedTransactionData(default_test_tx_details::<S>());
    let mut context = Context::<S>::with_payer(
        sender,
        Credentials::default(),
        setup.sequencer.as_user().address(),
        setup.sequencer.da_address,
        payer,
        None,
        ExecutionContext::Node,
        SequencerType::NonPreferred,
    );

    let sender_balance_before = TestRunner::<RT, S>::bank_gas_balance(&sender, &mut checkpoint)
        .expect("sender should have a gas account");
    let payer_balance_before = TestRunner::<RT, S>::bank_gas_balance(&payer, &mut checkpoint)
        .expect("payer should have a gas account");

    runtime
        .gas_enforcer()
        .try_reserve_gas(
            &tx,
            <S as GasSpec>::initial_base_fee_per_gas(),
            &mut context,
            &mut checkpoint,
        )
        .expect("gas reservation should succeed via the override branch");

    let sender_balance_after = TestRunner::<RT, S>::bank_gas_balance(&sender, &mut checkpoint)
        .expect("sender should still have a gas account");
    let payer_balance_after = TestRunner::<RT, S>::bank_gas_balance(&payer, &mut checkpoint)
        .expect("payer should still have a gas account");

    assert_eq!(sender_balance_after, sender_balance_before);
    assert_eq!(
        payer_balance_after,
        payer_balance_before
            .checked_sub(tx.0.max_fee)
            .expect("reservation should deduct max_fee from the override payer"),
    );
    assert_eq!(context.gas_refund_recipient(), &payer);

    // If the paymaster path had been consulted, the one-shot allowance would have been
    // decremented and persisted as a deny policy for this sender.
    let policy_key: sov_paymaster::PolicyKey<_> =
        format!("payers/{payer}/policy/{sender}").parse().unwrap();
    let mutated_policy = runtime
        .paymaster
        .policies
        .get(&policy_key, &mut checkpoint)
        .unwrap();
    assert_eq!(mutated_policy, None);
}

#[test]
fn test_pre_reserve_gas_failure_returns_pre_reserve_gas_failed() {
    let setup = setup(TEST_DEFAULT_USER_BALANCE);
    let runner: TestRunner<RT, S> = TestRunner::new_with_genesis(
        setup.genesis_config.into_genesis_params(),
        PaymasterRuntime::default(),
    );

    let mut runtime = FailingPreReserveRuntime::<S>::default();
    let storage = runner.storage_manager().create_prover_storage();
    let checkpoint = StateCheckpoint::<S>::new(storage, &runtime.kernel(), None);
    let scratchpad = checkpoint.to_tx_scratchpad();

    let raw_tx = setup
        .user
        .create_plain_message::<RT, ValueSetter<S>>(ValueSetterCallMessage::SetValue {
            value: 99,
            gas: None,
        })
        .to_serialized_authenticated_tx(&mut HashMap::new());

    let gas_price = <S as GasSpec>::initial_base_fee_per_gas();
    let pre_exec_gas_meter =
        BasicGasMeter::new_with_gas(<S as GasSpec>::max_tx_check_costs(), gas_price);
    let mut pre_exec_working_set = scratchpad.to_pre_exec_working_set(pre_exec_gas_meter);
    pre_exec_working_set
        .charge_gas(<S as GasSpec>::process_tx_pre_exec_checks_gas())
        .expect("the pre-exec meter should cover authentication costs in this test");

    let validated_output = <FailingPreReserveRuntime<S> as Runtime<S>>::Auth::authenticate(
        &raw_tx,
        &mut pre_exec_working_set,
    )
    .expect("transaction authentication should succeed before the hook failure is exercised");

    let metrics = AuthAndProcessMetrics::new(
        validated_output.0.raw_tx_hash.into(),
        AuthAndProcessTimings::new_with_defaults(ExecutionContext::Node.str()),
    );

    let (result, mut scratchpad, _pre_exec_gas_meter) = process_tx_and_reward_prover(
        &mut runtime,
        pre_exec_working_set,
        <S as Spec>::Gas::max(),
        validated_output,
        raw_tx,
        &setup.sequencer.da_address,
        setup.sequencer.as_user().address(),
        ExecutionContext::Node,
        &NoOpControlFlow,
        OperatingMode::Optimistic,
        metrics,
        SequencerType::NonPreferred,
    );

    let (error, _raw_tx) = result.expect_err("the failing hook should skip the transaction");
    assert_eq!(
        error,
        TxProcessingError::PreReserveGasFailed("delegated billing denied".to_string()),
    );
    assert_eq!(
        runtime
            .inner
            .value_setter
            .value
            .get(&mut scratchpad)
            .unwrap(),
        None,
        "pre_reserve_gas writes should be reverted on hook failure",
    );
}
