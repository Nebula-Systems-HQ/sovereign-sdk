//! Layered revertable transaction state implementation.

use std::collections::HashMap;
use std::marker::PhantomData;

use sov_metrics::{StateAccessMetric, StateMetrics};
use sov_state::{
    EventContainer, Kernel as KernelType, Namespace, SlotKey, SlotValue, TypeErasedEvent, User,
};

use super::super::temp_cache::{CacheLookup, TempCache};
use super::super::{BorshSerializedSize, StateMetricsProvider, UniversalStateAccessor};
use crate::module::Spec;
use crate::state::traits::delegate_version_reader;
use crate::state::traits::PerBlockCache;
use crate::transaction::PriorityFeeBips;
use crate::{
    AccessoryStateWriter, Amount, BasicGasMeter, Gas, GasArray, GasBiller, GasBillingError,
    GasMeter, GasMeteringError, ProvableStateReader, ProvableStateWriter, TxState,
};

#[cfg(feature = "test-utils")]
use crate::AccessoryStateReader;

/// A snapshot of gas meter state at layer creation time.
///
/// Used for both gas-payer and gas-free layers:
/// - **Gas-payer**: billing (upfront charge + refund) + exact meter restoration
/// - **Gas-free**: exact meter restoration only (no billing)
///
/// Both paths restore the meter exactly on settlement — sub-call gas consumption
/// does NOT affect the outer meter.
#[derive(Clone, Debug)]
pub struct GasSnapshot<S: Spec> {
    /// Outer payer's initial gas (to restore on layer end).
    pub outer_initial_gas: S::Gas,
    /// Outer payer's remaining gas (to restore on layer end).
    pub outer_remaining_gas: S::Gas,
    /// Outer payer's remaining funds (to restore on layer end).
    /// `None` when funds tracking is not enabled (e.g. gas-free layers in tests).
    pub outer_remaining_funds: Option<Amount>,
    /// Amount charged upfront when layer was created (for refund calculation).
    /// Includes both base gas cost and priority fee reservation.
    pub upfront_charge: Amount,
    /// Gas price at layer creation (for refund calculation).
    pub gas_price: <S::Gas as Gas>::Price,
    /// Priority fee rate in basis points (1 bip = 0.01%).
    pub priority_fee_bips: PriorityFeeBips,
}

/// Billing info extracted from a layer before it's consumed (committed/reverted).
/// Used to decouple billing from layer mutation so we can bill using `self.inner`
/// after the layer has been committed or reverted.
#[derive(Clone, Debug)]
struct GasBillingInfo<S: Spec> {
    gas_payer: S::Address,
    gas_snapshot: GasSnapshot<S>,
    gas_consumed: S::Gas,
}

/// Error type for gas payer layer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasPayerError<G: Gas> {
    /// Insufficient gas available for the requested gas limit.
    InsufficientGas {
        /// The gas limit requested.
        required: G,
        /// The gas available in the meter.
        available: G,
    },
    /// Gas payer account does not have enough balance.
    InsufficientPayerBalance {
        /// The funds required for this layer.
        required: Amount,
        /// The gas payer's balance.
        available: Amount,
    },
    /// Gas payer account does not exist.
    PayerAccountNotFound {
        /// String representation of the payer address.
        payer: String,
    },
    /// Gas billing error during layer operations.
    BillingError(GasBillingError),
    /// Funds tracking is not enabled on the gas meter.
    FundsTrackingNotEnabled,
}

impl<G: Gas> std::fmt::Display for GasPayerError<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientGas {
                required,
                available,
            } => {
                write!(
                    f,
                    "Insufficient gas: required {:?}, available {:?}",
                    required, available
                )
            }
            Self::InsufficientPayerBalance {
                required,
                available,
            } => {
                write!(
                    f,
                    "Gas payer has insufficient balance: required {}, available {}",
                    required, available
                )
            }
            Self::PayerAccountNotFound { payer } => {
                write!(f, "Gas payer account not found: {}", payer)
            }
            Self::BillingError(e) => write!(f, "Gas billing error: {}", e),
            Self::FundsTrackingNotEnabled => {
                write!(f, "Funds tracking is not enabled on the gas meter")
            }
        }
    }
}

impl<G: Gas> std::error::Error for GasPayerError<G> {}

impl<G: Gas> From<GasBillingError> for GasPayerError<G> {
    fn from(e: GasBillingError) -> Self {
        Self::BillingError(e)
    }
}

/// A single layer of state changes that can be committed or reverted.
///
/// Layer types (distinguished by field combinations):
/// - **Plain**: `gas_payer = None`, `gas_snapshot = None` — no meter swap, no restore
/// - **Gas-payer**: `gas_payer = Some(addr)`, `gas_snapshot = Some(snap)` — billing + exact restore
/// - **Gas-free**: `gas_payer = None`, `gas_snapshot = Some(snap)` — no billing, exact restore
#[derive(Debug)]
pub(super) struct StateLayer<S: Spec> {
    events: Vec<TypeErasedEvent>,
    temp_cache: TempCache,
    writes: HashMap<(Namespace, SlotKey), Option<SlotValue>>,
    /// The gas payer for this layer (if different from outer layer).
    /// Used for billing the gas payer when the layer is settled.
    pub(super) gas_payer: Option<S::Address>,
    /// Gas consumed in this layer.
    /// Used for calculating the gas cost to bill to the gas payer.
    pub(super) gas_consumed: S::Gas,
    /// Gas snapshot taken at layer creation time.
    /// Contains the outer meter state for exact restoration on settlement.
    /// Present for both gas-payer and gas-free layers.
    pub(super) gas_snapshot: Option<GasSnapshot<S>>,
}

impl<S: Spec> StateLayer<S> {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            temp_cache: TempCache::new(),
            writes: HashMap::new(),
            gas_payer: None,
            gas_consumed: S::Gas::ZEROED,
            gas_snapshot: None,
        }
    }

    fn new_with_gas_payer(gas_payer: S::Address, gas_snapshot: GasSnapshot<S>) -> Self {
        Self {
            events: Vec::new(),
            temp_cache: TempCache::new(),
            writes: HashMap::new(),
            gas_payer: Some(gas_payer),
            gas_consumed: S::Gas::ZEROED,
            gas_snapshot: Some(gas_snapshot),
        }
    }

    fn new_gas_free(gas_snapshot: GasSnapshot<S>) -> Self {
        Self {
            events: Vec::new(),
            temp_cache: TempCache::new(),
            writes: HashMap::new(),
            gas_payer: None,
            gas_consumed: S::Gas::ZEROED,
            gas_snapshot: Some(gas_snapshot),
        }
    }
}

/// A multi-layered revertable state that wraps a [`TxState`] and tracks writes and events
/// across multiple layers using a vector-based approach to avoid unbounded recursion.
///
/// When initialized with [`LayeredRevertableTxState::new`], there are no layers and all operations
/// are applied directly to the inner state. Layers can be added via [`LayeredRevertableTxState::add_revertable_layer`],
/// and when layers exist, operations are applied to the outermost layer.
///
/// Changes can be committed or reverted layer by layer via [`LayeredRevertableTxState::commit_layer`]
/// and [`LayeredRevertableTxState::revert_layer`].
///
/// ## Gas tracking
/// When layers have a gas payer set via [`LayeredRevertableTxState::add_revertable_layer_with_gas_payer`],
/// the gas payer must have sufficient gas/funds validated upfront before the layer is created.
pub struct LayeredRevertableTxState<'a, S: Spec, State> {
    pub(super) inner: &'a mut State,
    pub(super) layers: Vec<StateLayer<S>>,
    pub(super) phantom: PhantomData<S>,
    /// Gas consumed by the most recent `try_with_gas_payer` call.
    /// Overwritten each time a gas-payer-billed layer is settled.
    last_gas_consumed: Option<S::Gas>,
}

impl<S: Spec, I: StateMetricsProvider> StateMetricsProvider for LayeredRevertableTxState<'_, S, I> {
    fn metrics(&mut self) -> &mut StateMetrics {
        self.inner.metrics()
    }
}

impl<'a, S: Spec, I: TxState<S>> LayeredRevertableTxState<'a, S, I> {
    /// Creates a new [`LayeredRevertableTxState`] from the provided [`TxState`] with no layers.
    ///
    /// When there are no layers, all operations are applied directly to the inner state.
    /// When layers are added via [`LayeredRevertableTxState::add_revertable_layer`], operations
    /// are applied to the outermost layer.
    ///
    /// # Important
    /// You *MUST* call [`LayeredRevertableTxState::commit_layer`] to save any changes made to layers.
    /// Changes made when there are no layers are applied directly to the inner state and do not need to be committed.
    pub fn new(inner: &'a mut I) -> Self {
        Self {
            inner,
            layers: Vec::new(),
            phantom: PhantomData,
            last_gas_consumed: None,
        }
    }

    /// Returns gas consumed by the most recent `try_with_gas_payer` call.
    /// Overwritten each time a gas-payer-billed layer is settled (committed or reverted).
    pub fn last_gas_consumed(&self) -> Option<S::Gas> {
        self.last_gas_consumed
    }

    /// Clears the last_gas_consumed value.
    /// Call before dispatching to prevent stale reads when a dispatch
    /// fails at layer creation (e.g. InsufficientPayerBalance).
    pub fn clear_last_gas_consumed(&mut self) {
        self.last_gas_consumed = None;
    }

    /// Adds a new revertable layer on top of the current layers.
    /// This pushes a new layer onto the layers stack.
    pub fn add_revertable_layer(&mut self) -> &mut Self {
        self.layers.push(StateLayer::new());
        self
    }

    /// Adds a gas-free revertable layer that does not consume gas from the parent meter.
    ///
    /// Used for system/module operations (clearing, liquidation, funding) dispatched
    /// as dependency calls without a gas payer. The meter is swapped to unlimited values
    /// so inner charges always succeed, and restored exactly on commit/revert.
    ///
    /// State changes (writes, events) still commit/revert normally.
    pub fn add_revertable_layer_gas_free(&mut self) -> &mut Self {
        let snapshot = if let Some(meter) = self.inner.try_as_basic_gas_meter() {
            let snap = GasSnapshot {
                outer_initial_gas: meter.initial_gas,
                outer_remaining_gas: meter.remaining_gas,
                outer_remaining_funds: meter.remaining_funds,
                upfront_charge: Amount::ZERO,
                gas_price: meter.gas_price,
                priority_fee_bips: PriorityFeeBips::ZERO,
            };
            meter.initial_gas = S::Gas::MAX;
            meter.remaining_gas = S::Gas::MAX;
            meter.remaining_funds = Some(Amount::MAX);
            snap
        } else {
            GasSnapshot {
                outer_initial_gas: S::Gas::MAX,
                outer_remaining_gas: S::Gas::MAX,
                outer_remaining_funds: None,
                upfront_charge: Amount::ZERO,
                gas_price: <S::Gas as Gas>::Price::ZEROED,
                priority_fee_bips: PriorityFeeBips::ZERO,
            }
        };
        self.layers.push(StateLayer::new_gas_free(snapshot));
        self
    }

    /// Adds a new revertable layer with a different gas payer on top of the current layers.
    ///
    /// This method performs a "meter swap" - switching the gas payer context for
    /// nested calls. Gas charged within this layer will be billed to the gas payer
    /// (User B), not the outer payer (User A).
    ///
    /// # Arguments
    /// * `gas_payer` - The address of the account paying for gas in this layer
    /// * `gas_limit` - The maximum gas this layer is allowed to consume
    /// * `biller` - Implementation of GasBiller (typically Bank) for reading balances
    ///
    /// # Returns
    /// * `Ok(&mut Self)` - Layer was created successfully
    /// * `Err(GasPayerError::InsufficientGas)` - Insufficient gas available in meter
    /// * `Err(GasPayerError::InsufficientPayerBalance)` - Gas payer can't afford gas_limit
    /// * `Err(GasPayerError::FundsTrackingNotEnabled)` - Funds tracking not enabled
    ///
    /// # Gas Billing Flow
    /// 1. Snapshot outer payer's meter state (remaining_gas, remaining_funds)
    /// 2. Read gas payer's (User B) balance from bank (using inner state)
    /// 3. Validate gas payer can afford gas_limit
    /// 4. Charge upfront: transfer gas_limit * gas_price from payer to sequencer
    /// 5. Swap meter's remaining_gas to gas_limit (independent budget for payer)
    /// 6. On layer settlement, refund unused gas: (gas_limit - gas_consumed) * gas_price
    pub fn add_revertable_layer_with_gas_payer<B: GasBiller<S>>(
        &mut self,
        gas_payer: S::Address,
        gas_limit: S::Gas,
        sequencer: &S::Address,
        biller: &mut B,
        priority_fee_bips: u64,
    ) -> Result<&mut Self, GasPayerError<S::Gas>> {
        let gas_snapshot = self.validate_and_swap_gas_payer(
            gas_payer,
            gas_limit,
            sequencer,
            biller,
            priority_fee_bips,
        )?;
        self.layers
            .push(StateLayer::new_with_gas_payer(gas_payer, gas_snapshot));
        Ok(self)
    }

    /// Validates gas limit, reads gas payer's balance, and performs the meter swap.
    ///
    /// This method uses sequential borrows on `self.inner` to avoid needing an
    /// external `billing_state` parameter:
    /// 1. Borrow meter → extract remaining_gas, gas_price, remaining_funds → drop borrow
    /// 2. Borrow self.inner as StateAccessor → read gas payer balance → drop borrow
    /// 3. Borrow meter again → perform the swap
    ///
    /// Returns the snapshot containing outer payer's state (for restoration on settlement).
    fn validate_and_swap_gas_payer<B: GasBiller<S>>(
        &mut self,
        gas_payer: S::Address,
        gas_limit: S::Gas,
        sequencer: &S::Address,
        biller: &mut B,
        priority_fee_bips: u64,
    ) -> Result<GasSnapshot<S>, GasPayerError<S::Gas>> {
        // Phase 1: Read meter values (borrow meter, extract values, drop borrow)
        let (initial_gas, remaining_gas, remaining_funds, gas_cost, gas_price) = {
            let meter = match self.inner.try_as_basic_gas_meter() {
                Some(m) => m,
                None => {
                    // No gas meter means no gas tracking - gas payer layers require a meter
                    return Err(GasPayerError::FundsTrackingNotEnabled);
                }
            };

            let gas_price = meter.gas_price;
            let gas_cost = gas_limit.value(gas_price);
            let remaining_funds = meter
                .remaining_funds
                .ok_or(GasPayerError::FundsTrackingNotEnabled)?;

            (
                meter.initial_gas,
                meter.remaining_gas,
                remaining_funds,
                gas_cost,
                gas_price,
            )
        }; // meter borrow dropped

        // Include priority fee in the upfront reservation so the full amount is locked
        // before execution. upfront = base_cost + priority_fee(base_cost)
        let priority_fee_bips = PriorityFeeBips(priority_fee_bips);
        let priority_reservation = priority_fee_bips.apply(gas_cost).unwrap_or(Amount::ZERO);
        let upfront_charge = Amount(gas_cost.0.saturating_add(priority_reservation.0));

        // Phase 2: Read gas payer's balance (borrow self.inner as StateAccessor)
        let payer_balance = biller
            .gas_balance_of(&gas_payer, self.inner)?
            .ok_or_else(|| GasPayerError::PayerAccountNotFound {
                payer: format!("{:?}", gas_payer),
            })?;

        // Validate gas payer can afford the gas limit + priority fee
        if payer_balance < upfront_charge {
            return Err(GasPayerError::InsufficientPayerBalance {
                required: upfront_charge,
                available: payer_balance,
            });
        }

        // Phase 3: Charge upfront - transfer upfront_charge from payer to sequencer
        // This ensures the payment is secured before execution begins
        if upfront_charge > Amount::ZERO {
            biller
                .transfer_gas_tokens(&gas_payer, sequencer, upfront_charge, self.inner)
                .map_err(GasPayerError::BillingError)?;
        }

        // Phase 4: Create snapshot and perform meter swap (borrow meter again)
        let snapshot = GasSnapshot {
            outer_initial_gas: initial_gas,
            outer_remaining_gas: remaining_gas,
            outer_remaining_funds: Some(remaining_funds),
            upfront_charge,
            gas_price,
            priority_fee_bips,
        };

        if let Some(meter) = self.inner.try_as_basic_gas_meter() {
            // Perform the meter swap: set remaining_funds to the upfront charge
            // and set remaining_gas to the requested gas_limit to give the gas payer
            // an independent budget (not constrained by outer meter's remaining_gas)
            meter.remaining_funds = Some(upfront_charge);
            meter.initial_gas = gas_limit;
            meter.remaining_gas = gas_limit;
        }

        Ok(snapshot)
    }

    /// Extract billing info from the top layer (before it's consumed).
    /// Returns `None` if there's no layer or the layer has no gas payer.
    /// Takes ownership of gas_payer and gas_snapshot so the layer is clean
    /// before delegation to commit/revert_layer_without_billing.
    fn extract_gas_billing_info(&mut self) -> Option<GasBillingInfo<S>> {
        let layer = self.layers.last_mut()?;
        Some(GasBillingInfo {
            gas_payer: layer.gas_payer.take()?,
            gas_snapshot: layer.gas_snapshot.take()?,
            gas_consumed: layer.gas_consumed,
        })
    }

    /// Apply gas billing using `self.inner` as the state accessor.
    /// Called AFTER layer commit/revert so writes go to final inner state.
    ///
    /// Since gas was charged upfront at layer creation, this method calculates
    /// the refund and transfers it back from sequencer to payer.
    ///
    /// This method uses sequential borrows on `self.inner`:
    /// 1. Calculate actual gas cost from gas_consumed and stored gas_price
    /// 2. Borrow self.inner as StateAccessor → transfer refund → drop borrow
    /// 3. Borrow meter → restore outer payer's meter state → drop borrow
    fn apply_gas_billing<B: GasBiller<S>>(
        &mut self,
        info: Option<GasBillingInfo<S>>,
        biller: &mut B,
        sequencer: &S::Address,
    ) -> Result<(), GasBillingError> {
        let Some(info) = info else {
            return Ok(());
        };

        // Phase 1: Calculate actual gas cost using stored gas_price
        let actual_cost = info.gas_consumed.value(info.gas_snapshot.gas_price);

        // Priority fee is charged on actual consumption only
        let actual_priority_fee = info
            .gas_snapshot
            .priority_fee_bips
            .apply(actual_cost)
            .unwrap_or(Amount::ZERO);
        let actual_total = Amount(actual_cost.0.saturating_add(actual_priority_fee.0));

        // Phase 2: Calculate and transfer refund (borrow self.inner as StateAccessor)
        // Upfront charge was already paid at layer creation, now refund unused portion
        // Refund = upfront - actual_total (unused base gas + unused priority fee reservation)
        let refund = info
            .gas_snapshot
            .upfront_charge
            .checked_sub(actual_total)
            .unwrap_or(Amount::ZERO);

        if refund > Amount::ZERO {
            biller.transfer_gas_tokens(sequencer, &info.gas_payer, refund, self.inner)?;
        }

        // Emit a single consolidated gas event for the net cost
        if actual_cost > Amount::ZERO {
            biller.emit_net_gas_event(
                &info.gas_payer,
                sequencer,
                actual_cost,
                info.gas_consumed,
                info.gas_snapshot.gas_price,
                self.inner,
            );
        }

        // Record actual gas consumed so callers can read it
        self.last_gas_consumed = Some(info.gas_consumed);

        // Phase 3: Exact restoration of outer payer's meter state.
        // Sub-call gas consumption does NOT affect the outer meter.
        self.restore_meter_from_snapshot(&info.gas_snapshot);

        Ok(())
    }

    /// Commits the top layer without billing. Use `commit_layer` for production code.
    ///
    /// This skips gas settlement - only use for layers without gas payers or in tests.
    ///
    /// # Panics
    /// Panics if there are no layers to commit.
    pub fn commit_layer_without_billing(&mut self) {
        if self.layers.is_empty() {
            panic!("Cannot commit layer: no layers exist");
        }

        let layer = self.layers.pop().unwrap();
        debug_assert!(
            layer.gas_payer.is_none(),
            "Use commit_layer() for layers with gas payers"
        );
        debug_assert!(
            layer.gas_snapshot.is_none(),
            "Use commit_layer_gas_free() for gas-free layers (have gas_snapshot but no gas_payer)"
        );
        self.commit_layer_internal(layer);
    }

    /// Reverts the top layer without billing. Use `revert_layer` for production code.
    ///
    /// This skips gas settlement - only use for plain layers (no gas payer, no gas snapshot).
    ///
    /// # Panics
    /// Panics if there are no layers to revert.
    pub fn revert_layer_without_billing(&mut self) {
        if self.layers.is_empty() {
            panic!("Cannot revert layer: no layers exist");
        }

        let layer = self.layers.last().unwrap();
        debug_assert!(
            layer.gas_payer.is_none(),
            "Use revert_layer() for layers with gas payers"
        );
        debug_assert!(
            layer.gas_snapshot.is_none(),
            "Use revert_layer_gas_free() for gas-free layers (have gas_snapshot but no gas_payer)"
        );
        self.layers.pop();
    }

    /// Commits the top gas-free layer, restoring the meter without deducting gas.
    ///
    /// State changes (writes, events) are committed normally. Gas consumed in
    /// this layer is zeroed before merge so it doesn't propagate to parent layers.
    ///
    /// # Panics
    /// Panics if there are no layers, or the top layer is not gas-free.
    pub fn commit_layer_gas_free(&mut self) {
        if self.layers.is_empty() {
            panic!("Cannot commit layer: no layers exist");
        }

        let mut layer = self.layers.pop().unwrap();
        debug_assert!(
            layer.gas_payer.is_none(),
            "Gas-free layers must not have a gas payer"
        );
        debug_assert!(
            layer.gas_snapshot.is_some(),
            "Gas-free layers must have a gas snapshot"
        );

        let snapshot = layer.gas_snapshot.take().unwrap();
        // Zero out gas_consumed so commit_layer_internal doesn't merge it upward.
        layer.gas_consumed = S::Gas::ZEROED;
        self.commit_layer_internal(layer);
        self.restore_meter_from_snapshot(&snapshot);
    }

    /// Reverts the top gas-free layer, restoring the meter without deducting gas.
    ///
    /// All state changes are discarded. The meter is restored to its pre-layer state.
    ///
    /// # Panics
    /// Panics if there are no layers, or the top layer is not gas-free.
    pub fn revert_layer_gas_free(&mut self) {
        if self.layers.is_empty() {
            panic!("Cannot revert layer: no layers exist");
        }

        let layer = self.layers.last().unwrap();
        debug_assert!(
            layer.gas_payer.is_none(),
            "Gas-free layers must not have a gas payer"
        );
        debug_assert!(
            layer.gas_snapshot.is_some(),
            "Gas-free layers must have a gas snapshot"
        );

        let snapshot = self.layers.pop().unwrap().gas_snapshot.unwrap();
        self.restore_meter_from_snapshot(&snapshot);
    }

    /// Restores the gas meter to the exact state captured in a snapshot.
    /// Used by both gas-payer (apply_gas_billing) and gas-free (commit/revert_layer_gas_free).
    fn restore_meter_from_snapshot(&mut self, snapshot: &GasSnapshot<S>) {
        if let Some(meter) = self.inner.try_as_basic_gas_meter() {
            meter.initial_gas = snapshot.outer_initial_gas;
            meter.remaining_gas = snapshot.outer_remaining_gas;
            meter.remaining_funds = snapshot.outer_remaining_funds;
        }
    }

    /// Commits the top layer, billing the gas payer if present.
    /// If the layer has no gas payer, billing is skipped and it behaves like
    /// `commit_layer_without_billing`.
    ///
    /// The billing is done AFTER the layer is committed. This ensures that gas billing
    /// writes go directly to `self.inner` (the final merged state), avoiding conflicts
    /// where layer commits could overwrite billing writes.
    ///
    /// # Arguments
    /// * `biller` - Implementation of GasBiller for transferring gas tokens
    /// * `sequencer` - The address to receive the gas payment (typically the sequencer/operator)
    ///
    /// # Panics
    /// Panics if there are no layers to commit.
    pub fn commit_layer<B: GasBiller<S>>(
        &mut self,
        biller: &mut B,
        sequencer: &S::Address,
    ) -> Result<(), GasBillingError> {
        let billing_info = self.extract_gas_billing_info();
        self.commit_layer_without_billing();
        self.apply_gas_billing(billing_info, biller, sequencer)
    }

    /// Reverts the top layer, billing the gas payer if present.
    /// If the layer has no gas payer, billing is skipped and it behaves like
    /// `revert_layer_without_billing`.
    ///
    /// The billing is done AFTER the layer is reverted. Execution writes are discarded
    /// first (revert), then billing writes go directly to `self.inner`.
    /// Gas consumption is permanent even on revert (EVM behavior).
    ///
    /// # Arguments
    /// * `biller` - Implementation of GasBiller for transferring gas tokens
    /// * `sequencer` - The address to receive the gas payment (typically the sequencer/operator)
    ///
    /// # Panics
    /// Panics if there are no layers to revert.
    pub fn revert_layer<B: GasBiller<S>>(
        &mut self,
        biller: &mut B,
        sequencer: &S::Address,
    ) -> Result<(), GasBillingError> {
        let billing_info = self.extract_gas_billing_info();
        self.revert_layer_without_billing();
        self.apply_gas_billing(billing_info, biller, sequencer)
    }

    /// Internal helper to commit a layer's state changes.
    fn commit_layer_internal(&mut self, layer: StateLayer<S>) {
        if self.layers.is_empty() {
            // This was the last layer, commit to inner state
            for event in layer.events {
                self.inner.add_type_erased_event(event);
            }
            for (key, value) in layer.writes {
                if let Some(value) = value {
                    self.inner.set_value(key.0, &key.1, value);
                } else {
                    self.inner.delete_value(key.0, &key.1);
                }
            }
            self.inner.update_cache_with(layer.temp_cache);
        } else {
            // Commit to the layer below
            let lower_layer = self.layers.last_mut().unwrap();

            // Merge events
            lower_layer.events.extend(layer.events);

            // Merge writes (top layer takes precedence)
            for (key, value) in layer.writes {
                lower_layer.writes.insert(key, value);
            }

            // Merge cache
            lower_layer.temp_cache.update_with(layer.temp_cache);

            // Merge gas consumed so gas payer layers bill for all nested gas
            if let Some(combined) = lower_layer.gas_consumed.checked_combine(layer.gas_consumed) {
                lower_layer.gas_consumed = combined;
            }
        }
    }

    /// Gets the current number of layers.
    /// Returns 0 if no layers have been added.
    pub fn layer_depth(&self) -> usize {
        self.layers.len()
    }

    /// Tracks gas consumption in the current layer (if any).
    /// This is a helper used by GasMeter implementations.
    fn track_gas_in_layer(&mut self, amount: S::Gas) -> Result<(), GasMeteringError<S::Gas>> {
        if let Some(layer) = self.layers.last_mut() {
            layer.gas_consumed = layer.gas_consumed.checked_combine(amount).ok_or_else(|| {
                GasMeteringError::Overflow("Gas consumption overflow in layer".to_string())
            })?;
        }
        Ok(())
    }

    /// Gets the current top layer for write operations.
    /// Panics if no layers exist (should only be called when layers are present).
    fn current_layer_mut(&mut self) -> &mut StateLayer<S> {
        self.layers
            .last_mut()
            .expect("LayeredRevertableTxState should have at least one layer")
    }
}

delegate_version_reader!(LayeredRevertableTxState<'_, S, I> where [S: Spec, I: TxState<S>] => inner);

impl<S: Spec, I: TxState<S>> UniversalStateAccessor for LayeredRevertableTxState<'_, S, I> {
    fn get_size(
        &mut self,
        namespace: Namespace,
        key: &SlotKey,
        metrics: &mut StateAccessMetric,
    ) -> Option<u32> {
        // Check layers from top to bottom for the most recent write
        for layer in self.layers.iter().rev() {
            if let Some(value) = layer.writes.get(&(namespace, key.clone())) {
                return value.as_ref().map(|v| v.size());
            }
        }
        // If not found in any layer, check the inner state
        self.inner.get_size(namespace, key, metrics)
    }

    fn get_value(
        &mut self,
        namespace: Namespace,
        key: &SlotKey,
        metrics: &mut StateAccessMetric,
    ) -> Option<SlotValue> {
        // Check layers from top to bottom for the most recent write
        for layer in self.layers.iter().rev() {
            if let Some(value) = layer.writes.get(&(namespace, key.clone())) {
                return value.clone();
            }
        }
        // If not found in any layer, check the inner state
        self.inner.get_value(namespace, key, metrics)
    }

    fn set_value(&mut self, namespace: Namespace, key: &SlotKey, value: SlotValue) {
        if self.layers.is_empty() {
            // No layers, write directly to inner state
            self.inner.set_value(namespace, key, value);
        } else {
            // Write to the current (top) layer
            self.current_layer_mut()
                .writes
                .insert((namespace, key.clone()), Some(value));
        }
    }

    fn delete_value(&mut self, namespace: Namespace, key: &SlotKey) {
        if self.layers.is_empty() {
            // No layers, delete directly from inner state
            self.inner.delete_value(namespace, key);
        } else {
            // Mark as deleted in the current (top) layer
            self.current_layer_mut()
                .writes
                .insert((namespace, key.clone()), None);
        }
    }
}

impl<S: Spec, I: TxState<S>> PerBlockCache for LayeredRevertableTxState<'_, S, I> {
    fn get_cached<T: 'static + Send + Sync>(&self, slot_key: Option<SlotKey>) -> Option<&T> {
        // Check layers from top to bottom for cached values
        for layer in self.layers.iter().rev() {
            match layer.temp_cache.get::<T>(slot_key.clone()) {
                CacheLookup::Hit(value) => return value,
                CacheLookup::Miss => continue,
            }
        }
        // If not found in any layer, check the inner state
        self.inner.get_cached::<T>(slot_key)
    }

    fn put_cached<T: 'static + Send + Sync + BorshSerializedSize>(
        &mut self,
        slot_key: Option<SlotKey>,
        value: T,
    ) {
        if self.layers.is_empty() {
            // No layers, cache directly in inner state
            self.inner.put_cached(slot_key, value);
        } else {
            // Cache in the current (top) layer
            self.current_layer_mut().temp_cache.set(slot_key, value);
        }
    }

    fn delete_cached<T: 'static + Send + Sync>(&mut self, slot_key: Option<SlotKey>) {
        if self.layers.is_empty() {
            // No layers, delete directly from inner state
            self.inner.delete_cached::<T>(slot_key);
        } else {
            // Delete from the current (top) layer
            self.current_layer_mut().temp_cache.delete::<T>(slot_key);
        }
    }

    fn update_cache_with(&mut self, other: TempCache) {
        if self.layers.is_empty() {
            // No layers, update inner state cache directly
            self.inner.update_cache_with(other);
        } else {
            // Update the current (top) layer's cache
            self.current_layer_mut().temp_cache.update_with(other);
        }
    }
}

impl<S: Spec, I: TxState<S>> EventContainer for LayeredRevertableTxState<'_, S, I> {
    fn add_event<E: 'static + core::marker::Send + core::marker::Sync>(
        &mut self,
        event_key: &str,
        event: E,
    ) {
        if self.layers.is_empty() {
            // No layers, add event directly to inner state
            self.inner.add_event(event_key, event);
        } else {
            // Add event to the current (top) layer
            self.current_layer_mut()
                .events
                .push(TypeErasedEvent::new(event_key, event));
        }
    }

    fn add_type_erased_event(&mut self, event: TypeErasedEvent) {
        if self.layers.is_empty() {
            // No layers, add event directly to inner state
            self.inner.add_type_erased_event(event);
        } else {
            // Add event to the current (top) layer
            self.current_layer_mut().events.push(event);
        }
    }
}

impl<S: Spec, I: TxState<S>> GasMeter for LayeredRevertableTxState<'_, S, I> {
    type Spec = S;

    fn charge_gas(&mut self, amount: S::Gas) -> Result<(), GasMeteringError<S::Gas>> {
        self.track_gas_in_layer(amount)?;
        self.inner.charge_gas(amount)
    }

    fn try_as_basic_gas_meter(&mut self) -> Option<&mut BasicGasMeter<Self::Spec>> {
        self.inner.try_as_basic_gas_meter()
    }

    fn charge_linear_gas(
        &mut self,
        amount: <Self::Spec as Spec>::Gas,
        parameter: u32,
    ) -> anyhow::Result<(), GasMeteringError<<Self::Spec as Spec>::Gas>> {
        if let Some(total) = amount.checked_scalar_product(parameter as u64) {
            self.track_gas_in_layer(total)?;
        }
        self.inner.charge_linear_gas(amount, parameter)
    }

    #[cfg(all(feature = "gas-constant-estimation", feature = "native"))]
    fn remove_gas_pattern(&mut self, amount: &<Self::Spec as Spec>::Gas, parameter: u32) {
        self.inner.remove_gas_pattern(amount, parameter);
    }
}

impl<S: Spec, I: TxState<S>> ProvableStateReader<User> for LayeredRevertableTxState<'_, S, I> {}
impl<S: Spec, I: TxState<S>> ProvableStateReader<KernelType>
    for LayeredRevertableTxState<'_, S, I>
{
}
impl<S: Spec, I: TxState<S>> ProvableStateWriter<User> for LayeredRevertableTxState<'_, S, I> {}
impl<S: Spec, I: TxState<S>> ProvableStateWriter<KernelType>
    for LayeredRevertableTxState<'_, S, I>
{
}
impl<S: Spec, I: TxState<S>> AccessoryStateWriter for LayeredRevertableTxState<'_, S, I> {}
impl<S: Spec, I: TxState<S>> crate::state::traits::PinnedCacheAccessor<S>
    for LayeredRevertableTxState<'_, S, I>
{
    fn pinned_cache_mut(&mut self) -> Option<&mut sov_state::pinned_cache::PinnedCache> {
        self.inner.pinned_cache_mut()
    }

    fn storage(&self) -> &S::Storage {
        self.inner.storage()
    }
}
// Note: `LayeredRevertableTxState` implements `TxState<S>` via the blanket implementation.
// The direct method `add_revertable_layer()` returns `&mut Self` and uses the vector-based
// approach to prevent unbounded recursion.

#[cfg(feature = "test-utils")]
impl<S: Spec, I: TxState<S>> AccessoryStateReader for LayeredRevertableTxState<'_, S, I> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::mocks::MockKernel;
    use crate::execution_mode::Native;
    use crate::state::accessors::scratchpad::WorkingSet;
    use crate::StateAccessor;
    use sov_state::namespaces::User;
    use sov_state::{CompileTimeNamespace, SlotKey, SlotValue};
    use sov_test_utils::storage::SimpleStorageManager;
    use sov_test_utils::{MockDaSpec, MockZkvm};

    type TestSpec = crate::default_spec::DefaultNomtSpec<MockDaSpec, MockZkvm, MockZkvm, Native>;

    /// Mock biller for testing gas payer layers without a real Bank.
    struct MockBiller {
        /// Balance to return for any address (None = account not found)
        balance: Option<Amount>,
        /// Track total amount transferred (for test assertions)
        total_transferred: Amount,
        /// Track total amount refunded (sequencer → payer transfers)
        total_refunded: Amount,
        /// The sequencer address, used to detect refund direction
        sequencer: Option<<TestSpec as crate::Spec>::Address>,
    }

    impl MockBiller {
        fn with_balance(balance: Amount) -> Self {
            Self {
                balance: Some(balance),
                total_transferred: Amount::ZERO,
                total_refunded: Amount::ZERO,
                sequencer: None,
            }
        }

        fn with_balance_and_sequencer(
            balance: Amount,
            sequencer: <TestSpec as crate::Spec>::Address,
        ) -> Self {
            Self {
                balance: Some(balance),
                total_transferred: Amount::ZERO,
                total_refunded: Amount::ZERO,
                sequencer: Some(sequencer),
            }
        }
    }

    impl<S: Spec> GasBiller<S> for MockBiller {
        fn gas_balance_of(
            &self,
            _address: &S::Address,
            _state: &mut impl StateAccessor,
        ) -> Result<Option<Amount>, GasBillingError> {
            Ok(self.balance)
        }

        fn transfer_gas_tokens(
            &mut self,
            from: &S::Address,
            _to: &S::Address,
            amount: Amount,
            _state: &mut impl StateAccessor,
        ) -> Result<(), GasBillingError> {
            self.total_transferred = self.total_transferred.checked_add(amount).unwrap();
            // Detect refund: sequencer is the sender
            if let Some(ref seq) = self.sequencer {
                let seq_bytes = borsh::to_vec(seq).unwrap();
                let from_bytes = borsh::to_vec(from).unwrap();
                if seq_bytes == from_bytes {
                    self.total_refunded = self.total_refunded.checked_add(amount).unwrap();
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_no_layers_direct_access() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state with no layers
        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);
        assert_eq!(layered_state.layer_depth(), 0);

        // Write some data - should go directly to inner state
        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        layered_state.set_value(namespace, &key, value.clone());

        // Verify it's in the inner state directly
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value.clone())
        );

        // Changes were applied directly to inner state, no commit needed
        // Verify the value is already in inner state
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value)
        );
    }

    #[test]
    #[should_panic(expected = "Cannot commit layer: no layers exist")]
    fn test_commit_with_no_layers_panics() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // This should panic - no layers to commit
        layered_state.commit_layer_without_billing();
    }

    #[test]
    fn test_add_layer_after_direct_access() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state with no layers
        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");

        // Write directly to inner (no layers)
        layered_state.set_value(namespace, &key, value1.clone());

        // Add a layer
        layered_state.add_revertable_layer();
        assert_eq!(layered_state.layer_depth(), 1);

        // Now writes go to the layer
        layered_state.set_value(namespace, &key, value2.clone());

        // Should see value2 (from layer)
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value2.clone())
        );

        // Revert the layer - should return LayeredRevertableTxState with no layers
        layered_state.revert_layer_without_billing();
        // Should have no layers now
        assert_eq!(layered_state.layer_depth(), 0);
        // Should see value1 from inner (direct write before layer was added)
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value1)
        );
    }

    #[test]
    fn test_single_layer_commit() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add a layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        // Write some data
        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        layered_state.set_value(namespace, &key, value.clone());

        // Commit the layer
        layered_state.commit_layer_without_billing();
        // Should have no layers now and value should be in inner state
        assert_eq!(layered_state.layer_depth(), 0);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value)
        );
    }

    #[test]
    fn test_single_layer_revert() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add a layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        // Write some data
        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        layered_state.set_value(namespace, &key, value.clone());

        // Revert the layer - should return LayeredRevertableTxState with no layers
        layered_state.revert_layer_without_billing();
        // Should have no layers now
        assert_eq!(layered_state.layer_depth(), 0);
        // The write should be gone (it was in the layer)
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(layered_state.get_value(namespace, &key, &mut metric), None);
    }

    #[test]
    fn test_multiple_layers_commit() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key1 = SlotKey::from_slice(b"key1");
        let key2 = SlotKey::from_slice(b"key2");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");
        let value2_updated = SlotValue::from("value2_updated");

        // Write to first layer
        layered_state.set_value(namespace, &key1, value1.clone());
        layered_state.set_value(namespace, &key2, value2.clone());

        // Add second layer (now layered_state has 2 layers)
        layered_state.add_revertable_layer();

        // Update key2 in second layer
        layered_state.set_value(namespace, &key2, value2_updated.clone());

        // Commit second layer - should return LayeredRevertableTxState with layer1 remaining
        layered_state.commit_layer_without_billing();

        // Verify the commit merged correctly - layer1 should now have the updated value
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key1, &mut metric),
            Some(value1.clone()),
            "key1 should still have value1"
        );
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key2, &mut metric),
            Some(value2_updated.clone()),
            "key2 should have been updated to value2_updated"
        );

        // Commit first layer - should return LayeredRevertableTxState with no layers
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 0);
        // Verify final state through the layered state
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key1, &mut metric),
            Some(value1),
            "key1 should be in final state"
        );
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key2, &mut metric),
            Some(value2_updated),
            "key2 should have updated value in final state"
        );
    }

    #[test]
    fn test_multiple_layers_revert() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key1 = SlotKey::from_slice(b"key1");
        let key2 = SlotKey::from_slice(b"key2");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");
        let value2_updated = SlotValue::from("value2_updated");

        // Write to first layer
        layered_state.set_value(namespace, &key1, value1.clone());
        layered_state.set_value(namespace, &key2, value2.clone());

        // Add second layer
        layered_state.add_revertable_layer();

        // Update key2 in second layer
        layered_state.set_value(namespace, &key2, value2_updated.clone());

        // Revert second layer - should return LayeredRevertableTxState with layer1 remaining
        layered_state.revert_layer_without_billing();

        // Verify the revert worked - should have original values from layer1
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key1, &mut metric),
            Some(value1.clone()),
            "key1 should still have value1"
        );
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key2, &mut metric),
            Some(value2.clone()),
            "key2 should have original value2 after revert"
        );

        // Commit first layer
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 0);
        // Verify final state through the layered state
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key1, &mut metric),
            Some(value1),
            "key1 should be in final state"
        );
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key2, &mut metric),
            Some(value2),
            "key2 should have original value2 in final state"
        );
    }

    #[test]
    fn test_layer_depth() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state (starts with 0 layers)
        let mut layered_state = working_set.to_revertable_layered();
        assert_eq!(layered_state.layer_depth(), 0);

        // Add first layer
        layered_state.add_revertable_layer();
        assert_eq!(layered_state.layer_depth(), 1);

        // Add second layer
        layered_state.add_revertable_layer();
        assert_eq!(layered_state.layer_depth(), 2);

        // Add third layer
        layered_state.add_revertable_layer();
        assert_eq!(layered_state.layer_depth(), 3);
    }

    #[test]
    fn test_event_isolation() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();
        layered_state.add_event("test", "event1");

        // Add second layer
        layered_state.add_revertable_layer();
        layered_state.add_event("test", "event2");

        // Revert second layer - event2 should be lost
        layered_state.revert_layer_without_billing();

        // Commit first layer - only event1 should remain
        layered_state.commit_layer_without_billing();
        // Events are committed to inner state, we can't easily verify them in this test
        // but the structure ensures proper isolation
    }

    #[test]
    fn test_cache_isolation() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();
        let cache_key = SlotKey::from_slice(b"cache_key");
        layered_state.put_cached(Some(cache_key.clone()), "cached_value1".to_string());

        // Add second layer
        layered_state.add_revertable_layer();
        layered_state.put_cached(Some(cache_key.clone()), "cached_value2".to_string());

        // Check that second layer sees its own value
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key.clone())),
            Some(&"cached_value2".to_string())
        );

        // Revert second layer
        layered_state.revert_layer_without_billing();

        // Should see first layer's cached value
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key)),
            Some(&"cached_value1".to_string())
        );
    }

    #[test]
    fn test_delete_operations() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add a layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        // Write a value
        layered_state.set_value(namespace, &key, value.clone());

        // Verify it exists
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value.clone())
        );

        // Delete it
        layered_state.delete_value(namespace, &key);

        // Verify it's gone
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(layered_state.get_value(namespace, &key, &mut metric), None);

        // Commit and verify delete is persisted
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 0);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            None,
            "Deleted value should not exist after commit"
        );
    }

    #[test]
    fn test_delete_then_write() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");

        // Write value1
        layered_state.set_value(namespace, &key, value1.clone());

        // Add second layer
        layered_state.add_revertable_layer();

        // Delete in second layer
        layered_state.delete_value(namespace, &key);

        // Verify it's deleted
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(layered_state.get_value(namespace, &key, &mut metric), None);

        // Write new value in second layer
        layered_state.set_value(namespace, &key, value2.clone());

        // Verify new value is visible
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value2.clone())
        );

        // Revert second layer - should restore value1
        layered_state.revert_layer_without_billing();

        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value1.clone())
        );
    }

    #[test]
    fn test_layer_precedence_read() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");
        let value3 = SlotValue::from("value3");

        // Write value1 in layer1
        layered_state.set_value(namespace, &key, value1.clone());

        // Add layer2
        layered_state.add_revertable_layer();
        layered_state.set_value(namespace, &key, value2.clone());

        // Add layer3
        layered_state.add_revertable_layer();
        layered_state.set_value(namespace, &key, value3.clone());

        // Should see value3 (top layer)
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value3.clone())
        );

        // Revert layer3 - should see value2
        layered_state.revert_layer_without_billing();
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value2.clone())
        );

        // Revert layer2 - should see value1
        layered_state.revert_layer_without_billing();
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value1.clone())
        );
    }

    #[test]
    fn test_read_from_inner_state() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"inner_key");
        let value = SlotValue::from("inner_value");

        // Write directly to working set (inner state)
        use crate::StateWriter;
        StateWriter::<User>::set(&mut working_set, &key, value.clone()).unwrap();

        // Create layered state
        let mut layered_state = working_set.to_revertable_layered();

        // Should be able to read from inner state
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value.clone())
        );
    }

    #[test]
    fn test_delete_from_inner_state() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"inner_key");
        let value = SlotValue::from("inner_value");

        // Write directly to working set (inner state)
        use crate::StateWriter;
        StateWriter::<User>::set(&mut working_set, &key, value.clone()).unwrap();

        // Create layered state and add a layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        // Verify it exists (readable from inner state)
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value.clone())
        );

        // Delete it in the layer
        layered_state.delete_value(namespace, &key);

        // Should be gone
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(layered_state.get_value(namespace, &key, &mut metric), None);

        // Commit and verify delete is persisted
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 0);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            None,
            "Deleted value from inner state should not exist after commit"
        );
    }

    #[test]
    fn test_cache_delete() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let mut layered_state = working_set.to_revertable_layered();
        let cache_key = SlotKey::from_slice(b"cache_key");

        // Put value in cache
        layered_state.put_cached(Some(cache_key.clone()), "cached_value".to_string());
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key.clone())),
            Some(&"cached_value".to_string())
        );

        // Delete from cache
        layered_state.delete_cached::<String>(Some(cache_key.clone()));
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key.clone())),
            None
        );
    }

    #[test]
    fn test_cache_precedence() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let mut layered_state = working_set.to_revertable_layered();
        let cache_key = SlotKey::from_slice(b"cache_key");

        // Put value1 in layer1
        layered_state.put_cached(Some(cache_key.clone()), "value1".to_string());

        // Add layer2
        layered_state.add_revertable_layer();
        layered_state.put_cached(Some(cache_key.clone()), "value2".to_string());

        // Should see value2 (top layer)
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key.clone())),
            Some(&"value2".to_string())
        );

        // Revert layer2 - should see value1
        layered_state.revert_layer_without_billing();
        assert_eq!(
            layered_state.get_cached::<String>(Some(cache_key)),
            Some(&"value1".to_string())
        );
    }

    #[test]
    fn test_get_size_consistency() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        let mut layered_state = working_set.to_revertable_layered();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        // Write value
        layered_state.set_value(namespace, &key, value.clone());

        // get_size and get_value should be consistent
        let mut size_metric = StateAccessMetric::new_size();
        let size = layered_state.get_size(namespace, &key, &mut size_metric);
        let mut read_metric = StateAccessMetric::new_read();
        let retrieved_value = layered_state.get_value(namespace, &key, &mut read_metric);

        assert_eq!(size, retrieved_value.as_ref().map(|v| v.size()));
    }

    #[test]
    fn test_three_layers() {
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_kernel(storage, &MockKernel::<TestSpec>::default());

        // Create layered state and add first layer
        let mut layered_state = working_set.to_revertable_layered();
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value1 = SlotValue::from("value1");
        let value2 = SlotValue::from("value2");
        let value3 = SlotValue::from("value3");

        // Write value1 in layer1
        layered_state.set_value(namespace, &key, value1.clone());

        // Add layer2
        layered_state.add_revertable_layer();
        layered_state.set_value(namespace, &key, value2.clone());

        // Add layer3
        layered_state.add_revertable_layer();
        layered_state.set_value(namespace, &key, value3.clone());

        assert_eq!(layered_state.layer_depth(), 3);

        // Commit layer3 -> layer2
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 2);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value3.clone())
        );

        // Commit layer2 -> layer1
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 1);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value3.clone())
        );

        // Commit layer1 -> inner state
        layered_state.commit_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 0);
        let mut metric = StateAccessMetric::new_read();
        assert_eq!(
            layered_state.get_value(namespace, &key, &mut metric),
            Some(value3)
        );
    }

    #[test]
    fn test_gas_payer_layer_creation() {
        use crate::{Amount, Gas, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create working set with gas meter (funds tracking required for gas payer layers)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        // Create a layered state
        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // Create a dummy gas payer address and sequencer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);

        // Add layer with gas payer and gas limit
        let gas_limit = <TestSpec as Spec>::Gas::ZEROED;
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(
                gas_payer.clone(),
                gas_limit,
                &sequencer,
                &mut biller,
                0,
            )
            .unwrap();

        assert_eq!(layered_state.layer_depth(), 1);

        // Verify the layer has a gas payer
        let layer = &layered_state.layers[0];
        assert!(layer.gas_payer.is_some());
        assert_eq!(layer.gas_payer.as_ref().unwrap(), &gas_payer);
        assert!(layer.gas_snapshot.is_some());
    }

    #[test]
    fn test_gas_payer_layer_state_operations() {
        use crate::{Amount, Gas, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create working set with gas meter (funds tracking required for gas payer layers)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        // Add layer with gas payer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::ZEROED;
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .unwrap();

        // Write data in gas payer layer
        layered_state.set_value(namespace, &key, value.clone());

        // Verify data is visible
        let mut metric = StateAccessMetric::new_read();
        let read_value = layered_state.get_value(namespace, &key, &mut metric);
        assert_eq!(read_value, Some(value.clone()));

        // Revert the layer
        layered_state.revert_layer_without_billing();

        // Data should be gone
        let mut metric = StateAccessMetric::new_read();
        let read_after_revert = layered_state.get_value(namespace, &key, &mut metric);
        assert_eq!(read_after_revert, None);
    }

    #[test]
    fn test_gas_payer_nested_layers() {
        use crate::{Amount, Gas, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create working set with gas meter (funds tracking required for gas payer layers)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let namespace = User::NAMESPACE;
        let outer_key = SlotKey::from_slice(b"outer_key");
        let inner_key = SlotKey::from_slice(b"inner_key");
        let outer_value = SlotValue::from("outer_value");
        let inner_value = SlotValue::from("inner_value");

        // Add outer layer (regular)
        layered_state.add_revertable_layer();
        layered_state.set_value(namespace, &outer_key, outer_value.clone());

        // Add inner layer with gas payer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([3u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::ZEROED;
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .unwrap();
        layered_state.set_value(namespace, &inner_key, inner_value.clone());

        assert_eq!(layered_state.layer_depth(), 2);

        // Both values should be visible
        let mut metric = StateAccessMetric::new_read();
        let outer_read = layered_state.get_value(namespace, &outer_key, &mut metric);
        let mut metric = StateAccessMetric::new_read();
        let inner_read = layered_state.get_value(namespace, &inner_key, &mut metric);
        assert_eq!(outer_read, Some(outer_value.clone()));
        assert_eq!(inner_read, Some(inner_value.clone()));

        // Revert inner layer (with gas payer)
        layered_state.revert_layer_without_billing();
        assert_eq!(layered_state.layer_depth(), 1);

        // Inner value should be gone, outer should remain
        let mut metric = StateAccessMetric::new_read();
        let inner_after = layered_state.get_value(namespace, &inner_key, &mut metric);
        let mut metric = StateAccessMetric::new_read();
        let outer_after = layered_state.get_value(namespace, &outer_key, &mut metric);
        assert_eq!(inner_after, None);
        assert_eq!(outer_after, Some(outer_value));
    }

    #[test]
    fn test_gas_payer_layer_commit() {
        use crate::{Amount, Gas, GasMeter, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create working set with gas meter (funds tracking required for gas payer layers)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        // Add layer with gas payer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::from([50u64, 50u64]);
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .unwrap();

        // Write data
        layered_state.set_value(namespace, &key, value.clone());

        // Charge some gas
        let gas_to_charge = <TestSpec as Spec>::Gas::from([20u64, 20u64]);
        if let Some(meter) = layered_state.inner.try_as_basic_gas_meter() {
            meter.charge_gas(gas_to_charge).expect("Should charge gas");
        }
        layered_state.track_gas_in_layer(gas_to_charge);

        // Commit the layer WITH BILLING
        layered_state
            .commit_layer(&mut biller, &sequencer)
            .expect("commit_layer should succeed");
        assert_eq!(layered_state.layer_depth(), 0);

        // Verify billing happened
        let expected_cost = gas_to_charge.value(gas_price);
        assert_eq!(
            biller.total_transferred, expected_cost,
            "Gas should be billed on commit"
        );

        // Data should still be visible (committed to inner state)
        let mut metric = StateAccessMetric::new_read();
        let read_value = layered_state.get_value(namespace, &key, &mut metric);
        assert_eq!(read_value, Some(value));
    }

    #[test]
    fn test_gas_consumed_tracking_in_layer() {
        use crate::{Amount, Gas, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create working set with gas meter (funds tracking required for gas payer layers)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // Add layer with gas payer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::ZEROED;
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .unwrap();

        // Initially, gas_consumed should be ZEROED
        let gas_consumed = &layered_state.layers[0].gas_consumed;
        assert_eq!(*gas_consumed, <TestSpec as crate::Spec>::Gas::ZEROED);
    }

    #[test]
    fn test_gas_payer_revert_restores_outer_funds() {
        use crate::{Amount, Gas, GasMeter, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create gas price and initial funds
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);

        // Create a working set WITH a gas meter that has actual funds
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        // Verify initial funds
        let meter = working_set.try_as_basic_gas_meter().unwrap();
        assert_eq!(meter.remaining_funds, Some(initial_funds));

        // Create layered state
        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // Add gas payer layer with gas_limit - this should snapshot the funds
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::from([100u64, 100u64]); // Well under our 1000 funds
        let mut biller = MockBiller::with_balance(Amount::MAX);
        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .unwrap();

        // Verify snapshot captured the OUTER payer's funds (before meter swap)
        let snapshot = layered_state.layers[0].gas_snapshot.as_ref().unwrap();
        assert_eq!(snapshot.outer_remaining_funds, initial_funds);

        // After meter swap, remaining_funds is now gas_cost (gas_limit * gas_price)
        // gas_limit = [100, 100], gas_price = [1, 1], so gas_cost = 200
        let gas_cost = Amount::new(200);
        let meter = layered_state.inner.try_as_basic_gas_meter().unwrap();
        assert_eq!(
            meter.remaining_funds,
            Some(gas_cost),
            "Meter should be swapped to gas_cost"
        );

        // Charge some gas - this should reduce remaining_funds from gas_cost
        // Note: charge_gas internally calls track_gas_in_layer
        let gas_to_charge = <TestSpec as Spec>::Gas::from([10u64, 10u64]);
        layered_state.charge_gas(gas_to_charge).unwrap();

        // Verify funds decreased from gas_cost, not initial_funds
        let meter = layered_state.inner.try_as_basic_gas_meter().unwrap();

        // Now revert the layer WITH BILLING - outer funds should be restored
        // minus the gas consumed (gas is permanent)
        layered_state
            .revert_layer(&mut biller, &sequencer)
            .expect("revert_layer should succeed");

        // Verify billing happened - gas is permanent even on revert
        let expected_billing = gas_to_charge.value(gas_price);
        assert_eq!(
            biller.total_transferred, expected_billing,
            "Gas should be billed even on revert"
        );

        // After revert, the outer payer's meter state is fully restored.
        // The gas was paid by the gas_payer via token transfer (biller),
        // NOT by reducing the outer meter's remaining_funds.
        let meter = layered_state.inner.try_as_basic_gas_meter().unwrap();
        assert_eq!(
            meter.remaining_funds,
            Some(initial_funds),
            "Outer funds should be fully restored (gas paid by gas_payer via token transfer)"
        );
    }

    #[test]
    fn test_gas_payer_upfront_validation_out_of_gas() {
        use crate::{Amount, Gas, GasMeter, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create gas price and HIGH initial funds (so we don't hit OutOfFunds first)
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(u64::MAX as u128); // Lots of funds

        // Create a working set with gas meter
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        // Set remaining gas to a small value directly for testing
        let meter = working_set.try_as_basic_gas_meter().unwrap();
        meter.remaining_gas = <TestSpec as Spec>::Gas::from([50u64, 50u64]);

        // Create layered state
        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let mut biller = MockBiller::with_balance(Amount::MAX);

        // Gas payer layers now get an independent gas budget, so even a gas_limit
        // exceeding outer remaining_gas (100 > 50) should succeed as long as payer
        // has sufficient balance
        let large_gas_limit = <TestSpec as Spec>::Gas::from([100u64, 100u64]);

        let result = layered_state.add_revertable_layer_with_gas_payer(
            gas_payer.clone(),
            large_gas_limit,
            &sequencer,
            &mut biller,
            0,
        );
        // Should succeed - gas payer gets independent budget
        assert!(
            result.is_ok(),
            "Should succeed - gas payer gets independent budget"
        );

        // Verify the meter was swapped to the new gas_limit (not constrained by outer)
        if let Some(meter) = layered_state.inner.try_as_basic_gas_meter() {
            assert_eq!(meter.remaining_gas, large_gas_limit);
        }
    }

    #[test]
    fn test_gas_payer_zero_gas_limit() {
        use crate::{Amount, Gas, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(1000);

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let mut biller = MockBiller::with_balance(Amount::MAX);

        // Zero gas limit should be allowed (no-op layer)
        let zero_gas_limit = <TestSpec as Spec>::Gas::ZEROED;

        let result = layered_state.add_revertable_layer_with_gas_payer(
            gas_payer,
            zero_gas_limit,
            &sequencer,
            &mut biller,
            0,
        );
        assert!(result.is_ok(), "Zero gas limit should be allowed");
    }

    #[test]
    fn test_commit_layer_with_billing() {
        use crate::{Amount, Gas, GasMeter, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // Create gas price and initial funds
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(10); 2]);
        let initial_funds = Amount::new(1000);

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // Set up gas payer layer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::from([50u64, 50u64]);
        let mut biller = MockBiller::with_balance(Amount::MAX);

        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .expect("Should create gas payer layer");

        // Simulate gas consumption by charging the meter
        if let Some(meter) = layered_state.inner.try_as_basic_gas_meter() {
            let gas_to_charge = <TestSpec as Spec>::Gas::from([20u64, 20u64]);
            meter.charge_gas(gas_to_charge).expect("Should charge gas");
        }

        // Track gas consumed in layer
        let gas_consumed = <TestSpec as Spec>::Gas::from([20u64, 20u64]);
        layered_state.track_gas_in_layer(gas_consumed);

        // Now commit with billing
        let result = layered_state.commit_layer(&mut biller, &sequencer);
        assert!(result.is_ok(), "commit_layer should succeed");

        // Verify billing happened
        // gas_consumed = [20, 20], gas_price = [10, 10]
        // cost = 20*10 + 20*10 = 400
        let expected_cost = gas_consumed.value(gas_price);
        assert_eq!(
            biller.total_transferred, expected_cost,
            "Should have transferred the correct gas cost"
        );
    }

    #[test]
    fn test_revert_layer_with_billing() {
        use crate::{Amount, Gas, GasMeter, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(5); 2]);
        let initial_funds = Amount::new(1000);

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");

        // Set up gas payer layer
        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::from([100u64, 100u64]);
        let mut biller = MockBiller::with_balance(Amount::MAX);

        layered_state
            .add_revertable_layer_with_gas_payer(gas_payer, gas_limit, &sequencer, &mut biller, 0)
            .expect("Should create gas payer layer");

        // Write some data (this will be reverted)
        layered_state.set_value(namespace, &key, value.clone());

        // Simulate gas consumption
        if let Some(meter) = layered_state.inner.try_as_basic_gas_meter() {
            let gas_to_charge = <TestSpec as Spec>::Gas::from([30u64, 30u64]);
            meter.charge_gas(gas_to_charge).expect("Should charge gas");
        }

        let gas_consumed = <TestSpec as Spec>::Gas::from([30u64, 30u64]);
        layered_state.track_gas_in_layer(gas_consumed);

        // Revert with billing - gas should still be charged!
        let result = layered_state.revert_layer(&mut biller, &sequencer);
        assert!(result.is_ok(), "revert_layer should succeed");

        // Verify state was reverted
        let mut metric = StateAccessMetric::new_read();
        let read_value = layered_state.get_value(namespace, &key, &mut metric);
        assert!(read_value.is_none(), "Data should be reverted");

        // But gas should still have been billed!
        let expected_cost = gas_consumed.value(gas_price);
        assert_eq!(
            biller.total_transferred, expected_cost,
            "Gas should be billed even on revert"
        );
    }

    #[test]
    fn test_commit_layer_skips_billing_when_no_gas_payer() {
        use crate::{Amount, Gas, Spec};

        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(10); 2]);
        let initial_funds = Amount::new(1000);

        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        // Add a regular layer (no gas payer)
        layered_state.add_revertable_layer();

        let namespace = User::NAMESPACE;
        let key = SlotKey::from_slice(b"test_key");
        let value = SlotValue::from("test_value");
        layered_state.set_value(namespace, &key, value.clone());

        // Commit with billing params, but no gas payer on layer
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let mut biller = MockBiller::with_balance(Amount::MAX);

        let result = layered_state.commit_layer(&mut biller, &sequencer);
        assert!(result.is_ok(), "commit_layer should succeed");

        // No billing should have occurred
        assert_eq!(
            biller.total_transferred,
            Amount::ZERO,
            "No billing for layer without gas payer"
        );

        // But data should be committed
        let mut metric = StateAccessMetric::new_read();
        let read_value = layered_state.get_value(namespace, &key, &mut metric);
        assert_eq!(read_value, Some(value), "Data should be committed");
    }

    #[test]
    fn test_priority_fee_bips_billing() {
        use crate::{Amount, Gas, GasMeter, Spec};
        let storage_manager = SimpleStorageManager::new();
        let storage = storage_manager.create_storage();

        // gas_price = 1 per dimension, so gas cost = sum of dimension values
        let gas_price = <<TestSpec as Spec>::Gas as Gas>::Price::from([Amount::new(1); 2]);
        let initial_funds = Amount::new(10_000);
        let mut working_set =
            WorkingSet::<TestSpec>::new_with_gas_meter(storage, initial_funds, &gas_price);

        let mut layered_state = LayeredRevertableTxState::new(&mut working_set);

        let gas_payer = <TestSpec as crate::Spec>::Address::from([1u8; 28]);
        let sequencer = <TestSpec as crate::Spec>::Address::from([2u8; 28]);
        let gas_limit = <TestSpec as Spec>::Gas::from([100u64, 100u64]);

        // 500 bips = 5% priority fee
        let priority_fee_bips = 500u64;
        let mut biller = MockBiller::with_balance_and_sequencer(Amount::MAX, sequencer);

        layered_state
            .add_revertable_layer_with_gas_payer(
                gas_payer,
                gas_limit,
                &sequencer,
                &mut biller,
                priority_fee_bips,
            )
            .unwrap();

        // Upfront charge should be gas_cost + 5% = 200 + 10 = 210
        let gas_cost = gas_limit.value(gas_price); // 100*1 + 100*1 = 200
        let expected_upfront = Amount::new(gas_cost.0 + gas_cost.0 * 500 / 10_000); // 210
        assert_eq!(
            biller.total_transferred, expected_upfront,
            "Upfront charge should include 5% priority fee"
        );

        // Consume 40 gas per dimension (80 total cost at price=1)
        let gas_to_charge = <TestSpec as Spec>::Gas::from([40u64, 40u64]);
        if let Some(meter) = layered_state.inner.try_as_basic_gas_meter() {
            meter.charge_gas(gas_to_charge).expect("Should charge gas");
        }
        layered_state.track_gas_in_layer(gas_to_charge);

        // Commit — should refund unused portion
        layered_state
            .commit_layer(&mut biller, &sequencer)
            .expect("commit_layer should succeed");

        // actual_cost = 80, actual_priority = 80 * 500 / 10_000 = 4, actual_total = 84
        // refund = 210 - 84 = 126
        let actual_cost = gas_to_charge.value(gas_price); // 80
        let actual_priority = Amount::new(actual_cost.0 * 500 / 10_000); // 4
        let actual_total = Amount::new(actual_cost.0 + actual_priority.0); // 84
        let expected_refund = Amount::new(expected_upfront.0 - actual_total.0); // 126

        assert_eq!(
            biller.total_refunded, expected_refund,
            "Refund should return unused gas + unused priority fee reservation"
        );

        // Net cost to payer = upfront - refund = actual_total = 84
        let net_cost = Amount::new(expected_upfront.0 - biller.total_refunded.0);
        assert_eq!(
            net_cost, actual_total,
            "Net cost should equal actual gas + actual priority fee"
        );
    }
}
