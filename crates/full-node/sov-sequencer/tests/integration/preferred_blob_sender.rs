use std::env;
use std::pin::Pin;
use std::time::Duration;

use borsh::BorshDeserialize;
use futures::{Stream, StreamExt};
use sov_blob_sender::{BlobExecutionStatus, BlobSelectorStatus, BlobSubmissionStatus};
use sov_blob_storage::{
    EncryptedPreferredBatchData, PreferredBatchData, ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
};
use sov_encryption::BatchEncryptionConfig;
use sov_mock_da::{BlockProducingConfig, MockDaSpec};
use sov_mock_zkvm::crypto::private_key::Ed25519PrivateKey;
use sov_modules_api::capabilities::TransactionAuthenticator;
use sov_modules_api::prelude::*;
use sov_modules_api::{DispatchCall, FullyBakedTx, RawTx, Runtime};
use sov_modules_stf_blueprint::GenesisParams;
use sov_paymaster::PaymasterConfig;
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait};
use sov_rollup_interface::node::da::DaService;
use sov_rollup_interface::stf::BlobDiscardReason;
use sov_test_utils::runtime::genesis::optimistic::HighLevelOptimisticGenesisConfig;
use sov_test_utils::test_rollup::TestRollup;
use sov_test_utils::{
    default_test_signed_transaction_with_nonce, TestSpec, TestUser, TEST_BLOB_PROCESSING_TIMEOUT,
    TEST_MAX_BATCH_SIZE,
};
use sov_value_setter::ValueSetterConfig;

#[allow(unused_imports)]
use crate::preferred_end_to_end::{
    run_action_against_test_rollup, run_actions_against_test_rollup,
    setup_test_rollup_with_initial_state, InvalidGeneration, TestBlueprint, TestRuntime, TestState,
    TestingAction,
};
use crate::utils::{
    new_test_rollup, new_test_rollup_with_batch_encryption, tempdir_inside_codebase_dir,
    MAX_BATCH_EXECUTION_TIME_MILLIS,
};

type BlobStatusStream =
    Pin<Box<dyn Stream<Item = anyhow::Result<BlobExecutionStatus<MockDaSpec>>> + Send>>;

async fn create_test_rollup() -> (TestRollup<TestBlueprint>, TestUser<TestSpec>) {
    let genesis_config =
        HighLevelOptimisticGenesisConfig::generate().add_accounts_with_default_balance(1);
    let admin = genesis_config.additional_accounts()[0].clone();

    let rt_genesis_config =
        <TestRuntime<TestSpec> as Runtime<TestSpec>>::GenesisConfig::from_minimal_config(
            genesis_config.into(),
            ValueSetterConfig {
                admin: admin.address(),
            },
            (),
            PaymasterConfig::default(),
            (),
            (),
        );

    let genesis_params = GenesisParams {
        runtime: rt_genesis_config.clone(),
    };

    let dir = tempdir_inside_codebase_dir();

    (
        new_test_rollup::<TestRuntime<TestSpec>>(
            dir,
            genesis_params
                .runtime
                .sequencer_registry
                .sequencer_config
                .seq_da_address,
            genesis_params,
            0,
            true,
            TEST_MAX_BATCH_SIZE,
            BlockProducingConfig::Periodic { block_time_ms: 300 },
            //BlockProducingConfig::Manual,
            None,
            TEST_BLOB_PROCESSING_TIMEOUT,
            MAX_BATCH_EXECUTION_TIME_MILLIS,
            None,
            0,
        )
        .await,
        admin,
    )
}

async fn create_encrypted_test_rollup() -> (TestRollup<TestBlueprint>, TestUser<TestSpec>) {
    let genesis_config =
        HighLevelOptimisticGenesisConfig::generate().add_accounts_with_default_balance(1);
    let admin = genesis_config.additional_accounts()[0].clone();

    let rt_genesis_config =
        <TestRuntime<TestSpec> as Runtime<TestSpec>>::GenesisConfig::from_minimal_config(
            genesis_config.into(),
            ValueSetterConfig {
                admin: admin.address(),
            },
            (),
            PaymasterConfig::default(),
            (),
            (),
        );

    let genesis_params = GenesisParams {
        runtime: rt_genesis_config.clone(),
    };

    let dir = tempdir_inside_codebase_dir();

    let test_rollup = new_test_rollup_with_batch_encryption::<TestRuntime<TestSpec>>(
        dir,
        genesis_params
            .runtime
            .sequencer_registry
            .sequencer_config
            .seq_da_address,
        genesis_params,
        0,
        true,
        TEST_MAX_BATCH_SIZE,
        BlockProducingConfig::Periodic { block_time_ms: 300 },
        None,
        TEST_BLOB_PROCESSING_TIMEOUT,
        MAX_BATCH_EXECUTION_TIME_MILLIS,
        None,
        0,
        Some(BatchEncryptionConfig::Static {
            encryption_key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        }),
    )
    .await;

    (test_rollup, admin)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_discard_oversized_blobs() {
    env::set_var(
        "SOV_TEST_CONST_OVERRIDE_MAX_ALLOWED_DATA_SIZE_RETURNED_BY_BLOB_STORAGE",
        "1000",
    );
    let (test_rollup, admin) = create_test_rollup().await;

    test_rollup.produce_enough_finalized_slots().await;
    test_rollup.wait_for_sequencer_ready().await.unwrap();
    let client = test_rollup.api_client().clone();

    // Blob with this transaction will be discarded becuse the blob is bigger than `MAX_ALLOWED_DATA_SIZE_RETURNED_BY_BLOB_STORAGE`
    let tx = tx_set_many_values(&admin.private_key, 0, vec![7; 10000]);
    let _ = client.send_raw_tx_to_sequencer(&tx).await.unwrap();
    let mut sub = test_rollup
        .subscribe_to_blobs_from_blob_sender()
        .await
        .unwrap();

    tokio::time::timeout(tokio::time::Duration::from_secs(15), async {
        while let Some(blob_status) = sub.next().await {
            if let Some(BlobSelectorStatus::Discarded(BlobDiscardReason::OutOfCapacity)) =
                blob_status.as_ref().unwrap().blob_selector_status
            {
                break;
            }
        }
    })
    .await
    .expect("Timeout occurred while waiting for the discarded blob.");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_blobs_are_send_after_rollup_resync() {
    sov_test_utils::initialize_logging();
    let (test_rollup, _) = create_test_rollup().await;
    let da = test_rollup.da_service.clone();
    let mut header_subscription = da.subscribe_finalized_header().await.unwrap();

    for _ in 0..10 {
        da.produce_block_now().await.unwrap();
        header_subscription.next().await.unwrap().unwrap();
    }
    test_rollup.wait_for_node_synced().await.unwrap();

    let builder = test_rollup.shutdown().await.unwrap();

    // Generate a block while Rollup is offline to trigger resync logic.
    for _ in 0..20 {
        da.produce_block_now().await.unwrap();
        header_subscription.next().await.unwrap().unwrap();
    }

    // The new rollup has pending blobs in the BlobSender DB and completed blobs in the Preferred Sequencer state.
    let test_rollup = builder.start().await.unwrap();
    let mut subscribe_state_updates = test_rollup.subscribe_state_updates().await.unwrap();
    let mut subscribe_to_blobs_from_blob_sender = test_rollup
        .subscribe_to_blobs_from_blob_sender()
        .await
        .unwrap();

    // BlobSender should send blobs only after resync is complete, so the subscribe_state_updates notification must come first.
    tokio::select! {
        _ = subscribe_state_updates.next() => {}
        _ = subscribe_to_blobs_from_blob_sender.next() => {
            panic!("In a resync scenario, the state update notification should occur before the blob sender transmits the blobs.")
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_encrypted_preferred_batch_is_published_and_executed() {
    sov_test_utils::initialize_logging();
    let (test_rollup, admin) = create_encrypted_test_rollup().await;

    test_rollup.produce_enough_finalized_slots().await;
    test_rollup.wait_for_sequencer_ready().await.unwrap();

    let client = test_rollup.api_client().clone();
    let mut blob_statuses = test_rollup
        .subscribe_to_blobs_from_blob_sender()
        .await
        .unwrap();
    let head_before_tx = test_rollup
        .da_service
        .get_head_block_header()
        .await
        .unwrap()
        .height();
    let tx = tx_set_many_values(&admin.private_key, 0, vec![9, 9, 9]);
    client.send_raw_tx_to_sequencer(&tx).await.unwrap();

    wait_for_blob_sender_publication(&mut blob_statuses).await;
    let published_batch =
        wait_for_next_published_batch_blob(&test_rollup, head_before_tx, 20).await;
    assert_encrypted_preferred_batch_payload(&published_batch, &tx);

    wait_for_many_values_item(&test_rollup, 0, 9).await;
}

#[derive(Debug, serde::Deserialize)]
struct IdxResponse {
    #[allow(unused)]
    index: u64,
    value: Option<u8>,
}

async fn wait_for_next_published_batch_blob(
    test_rollup: &TestRollup<TestBlueprint>,
    start_height: u64,
    max_blocks_to_produce: u64,
) -> Vec<u8> {
    let mut next_height_to_scan = start_height + 1;

    for _ in 0..max_blocks_to_produce {
        test_rollup.da_service.produce_block_now().await.unwrap();
        let head = test_rollup
            .da_service
            .get_head_block_header()
            .await
            .unwrap()
            .height();

        for height in next_height_to_scan..=head {
            let mut block = test_rollup.da_service.get_block_at(height).await.unwrap();
            if let Some(blob) = block.batch_blobs.first_mut() {
                return blob.full_data().to_vec();
            }
        }

        next_height_to_scan = head + 1;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    panic!(
        "No batch blob was published within {max_blocks_to_produce} blocks after height {start_height}"
    );
}

async fn wait_for_blob_sender_publication(blob_statuses: &mut BlobStatusStream) {
    tokio::time::timeout(tokio::time::Duration::from_secs(15), async {
        while let Some(blob_status) = blob_statuses.next().await {
            let blob_status = blob_status.unwrap();
            if matches!(
                blob_status.blob_submission_status,
                BlobSubmissionStatus::Published { .. }
                    | BlobSubmissionStatus::Processed { .. }
                    | BlobSubmissionStatus::Finalized { .. }
            ) {
                return;
            }
        }

        panic!("Blob sender subscription closed before the batch was published");
    })
    .await
    .expect("Timed out waiting for blob sender to publish the batch");
}

fn assert_encrypted_preferred_batch_payload(blob_data: &[u8], tx: &RawTx) {
    let encrypted = EncryptedPreferredBatchData::try_from_slice(blob_data)
        .expect("published preferred batch blob must decode as encrypted batch data");
    assert!(
        PreferredBatchData::try_from_slice(blob_data).is_err(),
        "encrypted preferred batch blob must not decode as plaintext batch data"
    );
    assert_eq!(
        encrypted.encryption_format_version,
        ENCRYPTED_PREFERRED_BATCH_DATA_VERSION
    );

    let baked_tx =
        <<TestRuntime<TestSpec> as Runtime<TestSpec>>::Auth as TransactionAuthenticator<
            TestSpec,
        >>::encode_with_standard_auth(tx.clone());
    let plaintext_txs = borsh::to_vec::<Vec<FullyBakedTx>>(&vec![baked_tx])
        .expect("serializing plaintext tx vector should not fail");
    assert_no_subslice(
        blob_data,
        &plaintext_txs,
        "encrypted blob must not contain the serialized plaintext tx vector",
    );
    assert_no_subslice(
        blob_data,
        &tx.data,
        "encrypted blob must not contain the raw transaction bytes",
    );
}

fn assert_no_subslice(haystack: &[u8], needle: &[u8], message: &str) {
    assert!(
        needle.is_empty()
            || !haystack
                .windows(needle.len())
                .any(|window| window == needle),
        "{message}"
    );
}

async fn wait_for_many_values_item(
    test_rollup: &TestRollup<TestBlueprint>,
    index: u64,
    expected_value: u8,
) {
    let endpoint = format!("/modules/value-setter/state/many-values/items/{index}");

    tokio::time::timeout(tokio::time::Duration::from_secs(15), async {
        loop {
            if let Ok(response) = test_rollup
                .client
                .query_rest_endpoint::<IdxResponse>(&endpoint)
                .await
            {
                if response.value == Some(expected_value) {
                    return;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("Timed out waiting for many-values item {index} to become {expected_value}")
    });
}

fn tx_set_many_values(key: &Ed25519PrivateKey, nonce: u64, values_to_set: Vec<u8>) -> RawTx {
    let msg = <TestRuntime<TestSpec> as DispatchCall>::Decodable::ValueSetter(
        sov_value_setter::CallMessage::SetManyValues(values_to_set),
    );
    encode_call(key, nonce, &msg)
}

fn encode_call(
    key: &Ed25519PrivateKey,
    nonce: u64,
    call_message: &<TestRuntime<TestSpec> as DispatchCall>::Decodable,
) -> RawTx {
    let tx = default_test_signed_transaction_with_nonce::<TestRuntime<TestSpec>, TestSpec>(
        key,
        call_message,
        nonce,
        &<TestRuntime<TestSpec> as Runtime<TestSpec>>::CHAIN_HASH,
    );

    RawTx::new(borsh::to_vec(&tx).unwrap())
}
