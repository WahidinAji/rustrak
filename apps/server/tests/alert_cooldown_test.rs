//! Disabled cooldown must not suppress distinct events or weaken replay deduplication.
mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use rustrak::models::{
    AlertRuleChannelInput, AlertType, ChannelType, CreateAlertRule, CreateNotificationChannel,
    CreateProject,
};
use rustrak::services::grouping::DenormalizedFields;
use rustrak::services::{AlertService, IssueService, ProjectService};
use serde_json::json;
use uuid::Uuid;

async fn exercise_cooldown(
    minutes: i32,
    last_triggered_at: Option<DateTime<Utc>>,
    expected_skipped: i64,
) {
    let db = TestDb::new().await;
    let project = ProjectService::create(
        &db.pool,
        CreateProject {
            name: format!("Cooldown proof {}", Uuid::new_v4()),
            slug: None,
            platform: None,
        },
    )
    .await
    .unwrap();
    let channel = AlertService::create_channel(
        &db.pool,
        CreateNotificationChannel {
            name: "Local-only test sink".into(),
            provider_type: ChannelType::Webhook,
            credentials: json!({"url": "http://127.0.0.1:9/unused"}),
            is_enabled: true,
        },
    )
    .await
    .unwrap();
    let rule = AlertService::create_rule(
        &db.pool,
        project.id,
        CreateAlertRule {
            name: "Cooldown proof".into(),
            alert_type: AlertType::NewIssue,
            conditions: json!({}),
            cooldown_minutes: minutes,
            channels: vec![AlertRuleChannelInput {
                integration_id: channel.id,
                routing_override: json!({}),
            }],
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE alert_rules SET last_triggered_at = $1 WHERE id = $2")
        .bind(last_triggered_at)
        .bind(rule.id)
        .execute(&db.pool)
        .await
        .unwrap();
    for index in 0..2 {
        let issue = IssueService::create(
            &db.pool,
            project.id,
            Utc::now(),
            &DenormalizedFields {
                calculated_type: "Error".into(),
                calculated_value: format!("Distinct issue {index}"),
                transaction: "/test".into(),
                last_frame_filename: "test.rs".into(),
                last_frame_module: "test".into(),
                last_frame_function: "test".into(),
                culprit: "test".into(),
                logger: String::new(),
                release: String::new(),
            },
            Some("error"),
            Some("rust"),
        )
        .await
        .unwrap();
        let event = Uuid::new_v4();
        // Replaying the same occurrence still owns exactly one delivery record.
        for _ in 0..2 {
            AlertService::trigger_event_alert(
                &db.pool,
                &project,
                &issue,
                AlertType::NewIssue,
                event,
                "https://dashboard.example.invalid",
            )
            .await
            .unwrap();
        }
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_history WHERE project_id = $1")
        .bind(project.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let skipped: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM alert_history WHERE project_id = $1 AND status = 'skipped'",
    )
    .bind(project.id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(total, 2, "replays must not create duplicate deliveries");
    assert_eq!(
        skipped, expected_skipped,
        "only an enabled cooldown may suppress an alert"
    );
}

#[tokio::test]
async fn zero_cooldown_allows_distinct_alerts_after_clock_moves_backward() {
    // A future timestamp reproduces disabled cooldown deterministically on both
    // backends, without depending on calls landing in the same SQLite second.
    exercise_cooldown(0, Some(Utc::now() + Duration::minutes(1)), 0).await;
}

#[tokio::test]
async fn zero_cooldown_allows_first_and_subsequent_alerts() {
    exercise_cooldown(0, None, 0).await;
}

#[tokio::test]
async fn positive_cooldown_still_suppresses_and_deduplicates_replays() {
    exercise_cooldown(60, Some(Utc::now()), 2).await;
}

#[tokio::test]
async fn expired_positive_cooldown_allows_one_alert_and_restarts() {
    exercise_cooldown(60, Some(Utc::now() - Duration::minutes(61)), 1).await;
}
