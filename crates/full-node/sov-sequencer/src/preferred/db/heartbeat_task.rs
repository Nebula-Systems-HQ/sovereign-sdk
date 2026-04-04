//! Heartbeat and leadership tasks for sequencer nodes.
//!
//! This module provides periodic background tasks that maintain node presence
//! in the cluster and handle leadership transitions:
//!
//! - **Leader nodes** run a heartbeat to maintain leadership; if lost, they shut down.
//! - **DbElected replicas** run a heartbeat while competing for leadership; if acquired, they restart as leader.
//! - **Static replicas** run a heartbeat for registration only, never competing for leadership.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sov_full_node_configs::sequencer::{ConfiguredNodeRole, PostgresConfig};
use sov_rollup_interface::node::{future_or_shutdown, FutureOrShutdownOutput};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use super::SequencerRole;

use super::postgres::PostgresBackend;
use crate::preferred::exit_rollup;
use crate::SequencerNotReadyDetails;

#[derive(Debug, Clone)]
pub(crate) enum PromotionEligibility {
    Eligible,
    NotReady(SequencerNotReadyDetails),
    Unavailable(&'static str),
}

#[async_trait]
pub(crate) trait PromotionEligibilityChecker: Send + Sync + 'static {
    async fn promotion_eligibility(&self) -> PromotionEligibility;
}

/// Manages periodic heartbeat and optional leadership election for a sequencer node.
///
/// This task maintains the node's presence in the cluster by periodically updating
/// its registration in the database. Depending on the spawn method used, it may
/// also compete for leadership.
pub struct HeartBeatTask {
    backend: PostgresBackend,
    node_id: String,
    shutdown_sender: watch::Sender<()>,
    shutdown_receiver: watch::Receiver<()>,
    postgres_config: PostgresConfig,
    heartbeat_interval: Duration,
    promotion_eligibility_checker: Option<Arc<dyn PromotionEligibilityChecker>>,
}

impl HeartBeatTask {
    pub async fn new(
        postgres_config: PostgresConfig,
        shutdown_sender: watch::Sender<()>,
        bind_addr: SocketAddr,
        heartbeat_interval: Duration,
        promotion_eligibility_checker: Option<Arc<dyn PromotionEligibilityChecker>>,
    ) -> Result<Self> {
        let backend = PostgresBackend::connect(&postgres_config, bind_addr).await?;
        let shutdown_receiver = shutdown_sender.subscribe();

        Ok(Self {
            backend,
            node_id: postgres_config.node_id.clone(),
            shutdown_sender,
            shutdown_receiver,
            postgres_config,
            heartbeat_interval,
            promotion_eligibility_checker,
        })
    }

    /// Spawns heartbeat tasks based on the node's configured role.
    pub async fn spawn(self, seq_role: SequencerRole) -> JoinHandle<()> {
        let configures_node_role = self.postgres_config.node_role;
        match seq_role {
            SequencerRole::BatchProducer => self.spawn_leader_heartbeat_task(),
            SequencerRole::PgSyncReplica => {
                if configures_node_role == ConfiguredNodeRole::DbElected {
                    self.spawn_replica_heartbeat_task()
                } else {
                    assert_eq!(configures_node_role, ConfiguredNodeRole::Replica);
                    self.spawn_node_registration_task()
                }
            }
            SequencerRole::DaOnlyReplica => self.spawn_node_registration_task(),
        }
    }

    // Sends a heartbeat that competes for leadership.
    // Returns `true` if this node is the current leader.
    async fn try_acquire_leadership(&self) -> Result<bool> {
        match self
            .backend
            .heartbeat(Some(self.postgres_config.leader_election))
            .await?
        {
            Some(leader) => Ok(leader.node_id == self.node_id),
            None => Ok(false),
        }
    }

    // Sends a heartbeat that only updates node registration (no leadership competition).
    async fn register_node(&self) -> Result<()> {
        self.backend.heartbeat(None).await?;
        Ok(())
    }

    async fn should_attempt_leadership_acquisition(&self) -> bool {
        let Some(checker) = &self.promotion_eligibility_checker else {
            return true;
        };

        match checker.promotion_eligibility().await {
            PromotionEligibility::Eligible => true,
            PromotionEligibility::NotReady(SequencerNotReadyDetails::ReplicaNotReady) => {
                match self.backend.current_leader().await {
                    Ok(None) => match self.backend.sequencer_history_is_empty().await {
                        Ok(true) => {
                            info!(
                                node_id = %self.node_id,
                                "No leader row present and the shared sequencer DB is empty; allowing DbElected replica to bootstrap leadership while waiting for its first leader batch."
                            );
                            true
                        }
                        Ok(false) => {
                            debug!(
                                node_id = %self.node_id,
                                "No leader row present, but the shared sequencer DB contains history; skipping leadership acquisition until the replica is promotion-ready."
                            );
                            false
                        }
                        Err(e) => {
                            warn!(
                                node_id = %self.node_id,
                                error = ?e,
                                "Failed to inspect shared sequencer history while evaluating bootstrap eligibility; skipping leadership acquisition."
                            );
                            false
                        }
                    },
                    Ok(Some(current_leader)) => {
                        if !PostgresBackend::is_leader_fresh(
                            &current_leader,
                            self.postgres_config.leader_election.leader_timeout(),
                        ) {
                            match self.backend.sequencer_history_is_empty().await {
                                Ok(true) => {
                                    info!(
                                        node_id = %self.node_id,
                                        leader_node_id = %current_leader.node_id,
                                        last_updated = ?current_leader.last_updated,
                                        "Only a stale leader row is present and the shared sequencer DB is empty; allowing DbElected replica to bootstrap leadership while waiting for its first leader batch."
                                    );
                                    return true;
                                }
                                Ok(false) => {
                                    debug!(
                                        node_id = %self.node_id,
                                        leader_node_id = %current_leader.node_id,
                                        last_updated = ?current_leader.last_updated,
                                        "Only a stale leader row is present, but the shared sequencer DB contains history; skipping leadership acquisition until the replica is promotion-ready."
                                    );
                                    return false;
                                }
                                Err(e) => {
                                    warn!(
                                        node_id = %self.node_id,
                                        leader_node_id = %current_leader.node_id,
                                        error = ?e,
                                        "Failed to inspect shared sequencer history while evaluating stale-row bootstrap eligibility; skipping leadership acquisition."
                                    );
                                    return false;
                                }
                            }
                        }
                        debug!(
                            node_id = %self.node_id,
                            leader_node_id = %current_leader.node_id,
                            last_updated = ?current_leader.last_updated,
                            "Skipping leadership acquisition because the replica has not processed its first leader batch yet."
                        );
                        false
                    }
                    Err(e) => {
                        warn!(
                            node_id = %self.node_id,
                            error = ?e,
                            "Failed to read current leader while evaluating bootstrap eligibility; skipping leadership acquisition."
                        );
                        false
                    }
                }
            }
            PromotionEligibility::NotReady(details) => {
                debug!(
                    node_id = %self.node_id,
                    ?details,
                    "Skipping leadership acquisition because the node is not promotion-ready."
                );
                false
            }
            PromotionEligibility::Unavailable(reason) => {
                warn!(
                    node_id = %self.node_id,
                    reason,
                    "Skipping leadership acquisition because local readiness state is unavailable."
                );
                false
            }
        }
    }

    // Spawns a task for the current leader to maintain leadership.
    //
    // Periodically refreshes leadership. If leadership is lost or the database
    // becomes unreachable, triggers a graceful shutdown.  .
    fn spawn_leader_heartbeat_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!(node_id = %self.node_id, address = %self.backend.node_address, "Starting leader heartbeat task");
            let mut interval = tokio::time::interval(self.heartbeat_interval);

            loop {
                match future_or_shutdown(interval.tick(), &self.shutdown_receiver).await {
                    FutureOrShutdownOutput::Shutdown => {
                        info!("Shutdown signal received, stopping heartbeat task");
                        return;
                    }
                    FutureOrShutdownOutput::Output(_) => {
                        match self.try_acquire_leadership().await {
                            Ok(true) => {
                                // Successfully refreshed leadership and node registration
                                tracing::trace!("Leadership heartbeat successful.");
                            }
                            Ok(false) => {
                                error!(
                                    node_id = %self.node_id,
                                    "Leadership lost! Another node has taken over. Initiating graceful shutdown."
                                );
                                exit_rollup(&self.shutdown_sender).await;
                                unreachable!();
                            }
                            Err(e) => {
                                error!(
                                    node_id = %self.node_id,
                                    error = ?e,
                                    "Heartbeat error! Unable to communicate with database. Initiating graceful shutdown."
                                );
                                exit_rollup(&self.shutdown_sender).await;
                                unreachable!();
                            }
                        }
                    }
                }
            }
        })
    }

    // Spawns a task for a replica that wants to become leader.
    //
    // Periodically attempts to acquire leadership. If successful, triggers
    // a shutdown so the node can restart as the new leader.
    fn spawn_replica_heartbeat_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!(node_id = %self.node_id, address = %self.backend.node_address, "Starting replica election task");
            let mut interval = tokio::time::interval(self.heartbeat_interval);

            loop {
                match future_or_shutdown(interval.tick(), &self.shutdown_receiver).await {
                    FutureOrShutdownOutput::Shutdown => {
                        info!("Shutdown signal received, stopping election task.");
                        return;
                    }
                    FutureOrShutdownOutput::Output(_) => {
                        if self.should_attempt_leadership_acquisition().await {
                            match self.try_acquire_leadership().await {
                                Ok(true) => {
                                    info!(
                                        node_id = %self.node_id,
                                        "Replica acquired leadership! Exiting to restart as leader."
                                    );
                                    let _ = self.shutdown_sender.send(());
                                    break;
                                }
                                Ok(false) => {
                                    // Another node is still leader, keep trying
                                    trace!(
                                        "Leadership acquisition failed, another node is leader."
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        node_id = %self.node_id,
                                        error = ?e,
                                        "Election attempt failed, will retry."
                                    );
                                }
                            }
                        } else if let Err(e) = self.register_node().await {
                            warn!(
                                node_id = %self.node_id,
                                error = ?e,
                                "Node registration heartbeat failed while leadership acquisition was gated; will retry."
                            );
                        }
                    }
                }
            }
        })
    }

    // Spawns a task that only maintains node registration.
    //
    // Periodically updates the node's entry in the `nodes` table without
    // competing for leadership. Failures are logged but don't cause shutdown.
    fn spawn_node_registration_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!(node_id = %self.node_id, address = %self.backend.node_address, "Starting replica registration task.");
            let mut interval = tokio::time::interval(self.heartbeat_interval);

            loop {
                match future_or_shutdown(interval.tick(), &self.shutdown_receiver).await {
                    FutureOrShutdownOutput::Shutdown => {
                        info!("Shutdown signal received, stopping registration task.");
                        return;
                    }
                    FutureOrShutdownOutput::Output(_) => match self.register_node().await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!(
                                node_id = %self.node_id,
                                error = ?e,
                                "Node registration attempt failed, will retry."
                            );
                        }
                    },
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preferred::db::BatchToStore;
    use crate::preferred::db::DbBackend;
    use sov_full_node_configs::sequencer::LeaderElectionConfig;
    use sov_modules_api::VisibleSlotNumber;
    use sov_test_utils::postgres::{
        config_from_postgres_container, create_postgres_container, ContainerAsync,
        CreatePostgresError, Postgres,
    };
    use std::num::NonZero;
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};

    #[derive(Clone)]
    struct TestPromotionEligibilityChecker {
        state: Arc<Mutex<PromotionEligibility>>,
    }

    #[async_trait]
    impl PromotionEligibilityChecker for TestPromotionEligibilityChecker {
        async fn promotion_eligibility(&self) -> PromotionEligibility {
            self.state.lock().await.clone()
        }
    }

    impl TestPromotionEligibilityChecker {
        fn new(initial: PromotionEligibility) -> Self {
            Self {
                state: Arc::new(Mutex::new(initial)),
            }
        }

        async fn set(&self, next: PromotionEligibility) {
            *self.state.lock().await = next;
        }
    }

    async fn setup_test_postgres() -> Option<ContainerAsync<Postgres>> {
        match create_postgres_container().await {
            Ok(pg) => Some(pg),
            Err(CreatePostgresError::DockerNotSupported) => None,
            Err(CreatePostgresError::DockerError(e)) => {
                panic!("Failed to create Postgres container: {e}");
            }
        }
    }

    async fn postgres_config(postgres: &ContainerAsync<Postgres>, node_id: &str) -> PostgresConfig {
        let mut config = config_from_postgres_container(
            postgres,
            node_id.to_owned(),
            ConfiguredNodeRole::DbElected,
        )
        .await
        .unwrap();
        config.leader_election = LeaderElectionConfig {
            leader_timeout_millis: 100,
            grace_period_millis: 0,
            heartbeat_interval_millis: 25,
        };
        config
    }

    async fn create_cluster_history(config: &PostgresConfig, bind_addr: SocketAddr) {
        let mut backend = PostgresBackend::connect(config, bind_addr).await.unwrap();
        backend
            .heartbeat(Some(config.leader_election))
            .await
            .unwrap();

        let batch = BatchToStore {
            blob_id: 42,
            sequence_number: 1,
            visible_slot_number_after_increase: VisibleSlotNumber::new_dangerous(1),
            visible_slots_to_advance: NonZero::new(1).unwrap(),
        };

        backend.begin_rollup_block(batch).await.unwrap();
        backend.end_rollup_block(batch).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_replica_waits_for_readiness_before_taking_over() {
        let Some(postgres) = setup_test_postgres().await else {
            return;
        };

        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let leader_config = postgres_config(&postgres, "leader").await;
        let leader_backend = PostgresBackend::connect(&leader_config, bind_addr)
            .await
            .unwrap();
        leader_backend
            .heartbeat(Some(leader_config.leader_election))
            .await
            .unwrap();

        let replica_config = postgres_config(&postgres, "replica").await;
        let readiness_checker = TestPromotionEligibilityChecker::new(
            PromotionEligibility::NotReady(SequencerNotReadyDetails::Syncing {
                target_da_height: 10,
                synced_da_height: 1,
            }),
        );
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let heartbeat_task = HeartBeatTask::new(
            replica_config.clone(),
            shutdown_sender,
            bind_addr,
            replica_config.leader_election.heartbeat_interval(),
            Some(Arc::new(readiness_checker.clone())),
        )
        .await
        .unwrap();

        let heartbeat_handle = heartbeat_task.spawn(SequencerRole::PgSyncReplica).await;

        tokio::time::sleep(Duration::from_millis(250)).await;

        let inspector = PostgresBackend::connect(&replica_config, bind_addr)
            .await
            .unwrap();
        let registration_pool = sqlx::PgPool::connect(&replica_config.postgres_connection_string)
            .await
            .unwrap();
        let node_registration_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE node_id = $1")
                .bind("replica")
                .fetch_one(&registration_pool)
                .await
                .unwrap();
        assert_eq!(node_registration_count, 1);
        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "leader");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                shutdown_receiver.clone().changed()
            )
            .await
            .is_err(),
            "Replica should not restart while it is not promotion-ready",
        );

        readiness_checker.set(PromotionEligibility::Eligible).await;

        tokio::time::timeout(Duration::from_secs(2), heartbeat_handle)
            .await
            .expect("Timed out waiting for ready replica to acquire leadership")
            .unwrap();

        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "replica");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_replica_can_bootstrap_when_no_leader_row_exists() {
        let Some(postgres) = setup_test_postgres().await else {
            return;
        };

        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let replica_config = postgres_config(&postgres, "replica").await;
        let readiness_checker = TestPromotionEligibilityChecker::new(
            PromotionEligibility::NotReady(SequencerNotReadyDetails::ReplicaNotReady),
        );
        let (shutdown_sender, _) = watch::channel(());
        let heartbeat_task = HeartBeatTask::new(
            replica_config.clone(),
            shutdown_sender,
            bind_addr,
            replica_config.leader_election.heartbeat_interval(),
            Some(Arc::new(readiness_checker)),
        )
        .await
        .unwrap();

        let heartbeat_handle = heartbeat_task.spawn(SequencerRole::PgSyncReplica).await;

        tokio::time::timeout(Duration::from_secs(2), heartbeat_handle)
            .await
            .expect("Timed out waiting for bootstrap replica to acquire leadership")
            .unwrap();

        let inspector = PostgresBackend::connect(&replica_config, bind_addr)
            .await
            .unwrap();
        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "replica");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_replica_does_not_bootstrap_when_no_leader_row_exists_but_history_exists() {
        let Some(postgres) = setup_test_postgres().await else {
            return;
        };

        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let history_config = postgres_config(&postgres, "history-writer").await;
        create_cluster_history(&history_config, bind_addr).await;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let replica_config = postgres_config(&postgres, "replica").await;
        let readiness_checker = TestPromotionEligibilityChecker::new(
            PromotionEligibility::NotReady(SequencerNotReadyDetails::ReplicaNotReady),
        );
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let heartbeat_task = HeartBeatTask::new(
            replica_config.clone(),
            shutdown_sender.clone(),
            bind_addr,
            replica_config.leader_election.heartbeat_interval(),
            Some(Arc::new(readiness_checker)),
        )
        .await
        .unwrap();

        let heartbeat_handle = heartbeat_task.spawn(SequencerRole::PgSyncReplica).await;

        tokio::time::sleep(Duration::from_millis(250)).await;

        let inspector = PostgresBackend::connect(&replica_config, bind_addr)
            .await
            .unwrap();
        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "history-writer");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                shutdown_receiver.clone().changed()
            )
            .await
            .is_err(),
            "Replica should not restart while shared history exists and it is not promotion-ready",
        );

        shutdown_sender.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), heartbeat_handle)
            .await
            .expect("Timed out waiting for gated replica heartbeat task to stop")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_replica_can_bootstrap_when_only_stale_leader_row_exists() {
        let Some(postgres) = setup_test_postgres().await else {
            return;
        };

        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let stale_leader_config = postgres_config(&postgres, "stale-leader").await;
        let stale_leader_backend = PostgresBackend::connect(&stale_leader_config, bind_addr)
            .await
            .unwrap();
        stale_leader_backend
            .heartbeat(Some(stale_leader_config.leader_election))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let replica_config = postgres_config(&postgres, "replica").await;
        let readiness_checker = TestPromotionEligibilityChecker::new(
            PromotionEligibility::NotReady(SequencerNotReadyDetails::ReplicaNotReady),
        );
        let (shutdown_sender, _) = watch::channel(());
        let heartbeat_task = HeartBeatTask::new(
            replica_config.clone(),
            shutdown_sender,
            bind_addr,
            replica_config.leader_election.heartbeat_interval(),
            Some(Arc::new(readiness_checker)),
        )
        .await
        .unwrap();

        let heartbeat_handle = heartbeat_task.spawn(SequencerRole::PgSyncReplica).await;

        tokio::time::timeout(Duration::from_secs(2), heartbeat_handle)
            .await
            .expect("Timed out waiting for replica to replace a stale leader row")
            .unwrap();

        let inspector = PostgresBackend::connect(&replica_config, bind_addr)
            .await
            .unwrap();
        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "replica");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_replica_does_not_replace_stale_leader_row_when_history_exists() {
        let Some(postgres) = setup_test_postgres().await else {
            return;
        };

        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let stale_leader_config = postgres_config(&postgres, "stale-leader").await;
        create_cluster_history(&stale_leader_config, bind_addr).await;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let replica_config = postgres_config(&postgres, "replica").await;
        let readiness_checker = TestPromotionEligibilityChecker::new(
            PromotionEligibility::NotReady(SequencerNotReadyDetails::ReplicaNotReady),
        );
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let heartbeat_task = HeartBeatTask::new(
            replica_config.clone(),
            shutdown_sender.clone(),
            bind_addr,
            replica_config.leader_election.heartbeat_interval(),
            Some(Arc::new(readiness_checker)),
        )
        .await
        .unwrap();

        let heartbeat_handle = heartbeat_task.spawn(SequencerRole::PgSyncReplica).await;

        tokio::time::sleep(Duration::from_millis(250)).await;

        let inspector = PostgresBackend::connect(&replica_config, bind_addr)
            .await
            .unwrap();
        let current_leader = inspector.current_leader().await.unwrap().unwrap();
        assert_eq!(current_leader.node_id, "stale-leader");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                shutdown_receiver.clone().changed()
            )
            .await
            .is_err(),
            "Replica should not restart while shared history exists and only a stale leader row remains",
        );

        shutdown_sender.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), heartbeat_handle)
            .await
            .expect("Timed out waiting for stale-row gated replica heartbeat task to stop")
            .unwrap();
    }
}
