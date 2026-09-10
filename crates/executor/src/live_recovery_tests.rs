#[tokio::test]
#[ignore = "explicitly calls the configured official model API and consumes tokens"]
async fn official_model_recovery_on_benign_fixture() {
    super::native_recovery_tests::exercise_recovery(true).await;
}
