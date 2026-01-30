/// Outbox for queuing failed outbound emails with retry logic
///
/// Emails that fail to send are stored and retried every hour for up to 24 hours.
/// After 24 hours, a bounce message is generated and sent back to the sender.

use crate::client::config::get_storage_path;
use crate::client::smtp::MailTransaction;
use crate::{log_error, log_info};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Maximum age before giving up and bouncing (24 hours)
const MAX_RETRY_DURATION_HOURS: i64 = 24;

/// Retry interval (1 hour)
const RETRY_INTERVAL_HOURS: i64 = 1;

/// A queued outbound email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedEmail {
    /// Unique ID for this queued email
    pub id: String,
    /// Original sender (MAIL FROM)
    pub mail_from: String,
    /// Recipients (RCPT TO)
    pub rcpt_to: Vec<String>,
    /// Email data (headers + body)
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// When the email was first queued
    pub queued_at: DateTime<Utc>,
    /// When we last attempted to send
    pub last_attempt: DateTime<Utc>,
    /// Number of send attempts
    pub attempts: u32,
    /// Last error message
    pub last_error: String,
    /// Authenticated user who sent this
    pub authenticated_user: Option<String>,
}

/// Base64 serialization for Vec<u8>
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

impl QueuedEmail {
    /// Create a new queued email from a failed transaction
    pub fn from_transaction(transaction: &MailTransaction, error: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            mail_from: transaction.mail_from.clone(),
            rcpt_to: transaction.rcpt_to.clone(),
            data: transaction.data.clone(),
            queued_at: now,
            last_attempt: now,
            attempts: 1,
            last_error: error,
            authenticated_user: transaction.authenticated_user.clone(),
        }
    }

    /// Convert back to a MailTransaction for retry
    pub fn to_transaction(&self) -> MailTransaction {
        MailTransaction {
            mail_from: self.mail_from.clone(),
            rcpt_to: self.rcpt_to.clone(),
            data: self.data.clone(),
            is_outbound: true,
            authenticated_user: self.authenticated_user.clone(),
        }
    }

    /// Check if this email has exceeded the maximum retry duration
    pub fn is_expired(&self) -> bool {
        let age = Utc::now() - self.queued_at;
        age > Duration::hours(MAX_RETRY_DURATION_HOURS)
    }

    /// Check if enough time has passed for another retry attempt
    pub fn is_ready_for_retry(&self) -> bool {
        let since_last = Utc::now() - self.last_attempt;
        since_last >= Duration::hours(RETRY_INTERVAL_HOURS)
    }

    /// Record a failed attempt
    pub fn record_failure(&mut self, error: String) {
        self.last_attempt = Utc::now();
        self.attempts += 1;
        self.last_error = error;
    }
}

/// Outbox manager for queuing and retrying failed emails
pub struct Outbox {
    /// Path to the outbox directory
    outbox_path: PathBuf,
}

impl Outbox {
    /// Create a new outbox manager
    pub fn new() -> Self {
        let storage_path = get_storage_path();
        let outbox_path = storage_path.join("outbox");
        Self { outbox_path }
    }

    /// Ensure the outbox directory exists
    async fn ensure_dir(&self) -> Result<(), String> {
        fs::create_dir_all(&self.outbox_path)
            .await
            .map_err(|e| format!("Failed to create outbox directory: {}", e))
    }

    /// Queue a failed email for later retry
    pub async fn queue(&self, transaction: &MailTransaction, error: String) -> Result<String, String> {
        self.ensure_dir().await?;

        let queued = QueuedEmail::from_transaction(transaction, error);
        let id = queued.id.clone();
        let path = self.outbox_path.join(format!("{}.json", id));

        let json = serde_json::to_string_pretty(&queued)
            .map_err(|e| format!("Failed to serialize queued email: {}", e))?;

        fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write queued email: {}", e))?;

        log_info!(
            "Queued email {} for retry (from: {}, to: {:?})",
            id,
            queued.mail_from,
            queued.rcpt_to
        );

        Ok(id)
    }

    /// Load all queued emails
    pub async fn load_all(&self) -> Result<Vec<QueuedEmail>, String> {
        self.ensure_dir().await?;

        let mut entries = fs::read_dir(&self.outbox_path)
            .await
            .map_err(|e| format!("Failed to read outbox directory: {}", e))?;

        let mut queued = Vec::new();

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| format!("Failed to read directory entry: {}", e))?
        {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                match fs::read_to_string(&path).await {
                    Ok(json) => match serde_json::from_str::<QueuedEmail>(&json) {
                        Ok(email) => queued.push(email),
                        Err(e) => {
                            log_error!("Failed to parse queued email {:?}: {}", path, e);
                        }
                    },
                    Err(e) => {
                        log_error!("Failed to read queued email {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(queued)
    }

    /// Update a queued email after a retry attempt
    pub async fn update(&self, email: &QueuedEmail) -> Result<(), String> {
        let path = self.outbox_path.join(format!("{}.json", email.id));

        let json = serde_json::to_string_pretty(email)
            .map_err(|e| format!("Failed to serialize queued email: {}", e))?;

        fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write queued email: {}", e))
    }

    /// Remove a queued email (after successful send or bounce)
    pub async fn remove(&self, id: &str) -> Result<(), String> {
        let path = self.outbox_path.join(format!("{}.json", id));

        if path.exists() {
            fs::remove_file(&path)
                .await
                .map_err(|e| format!("Failed to remove queued email: {}", e))?;
        }

        Ok(())
    }

    /// Get the count of queued emails
    pub async fn count(&self) -> usize {
        match self.load_all().await {
            Ok(emails) => emails.len(),
            Err(_) => 0,
        }
    }
}

/// Generate a bounce message (DSN - Delivery Status Notification)
pub fn generate_bounce_message(queued: &QueuedEmail, hostname: &str) -> MailTransaction {
    let bounce_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let date = now.format("%a, %d %b %Y %H:%M:%S %z").to_string();

    // Extract original subject if possible
    let original_data = String::from_utf8_lossy(&queued.data);
    let _original_subject = original_data
        .lines()
        .find(|line| line.to_lowercase().starts_with("subject:"))
        .map(|line| line.trim_start_matches(|c: char| !c.is_whitespace()).trim())
        .unwrap_or("(no subject)");

    let recipients_list = queued.rcpt_to.join(", ");

    let body = format!(
        r#"From: Mail Delivery System <mailer-daemon@{hostname}>
To: {sender}
Subject: Undelivered Mail Returned to Sender
Date: {date}
Message-ID: <{bounce_id}@{hostname}>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status; boundary="boundary-{bounce_id}"
Auto-Submitted: auto-replied

This is a MIME-encapsulated message.

--boundary-{bounce_id}
Content-Type: text/plain; charset=utf-8

This message was created automatically by the mail system.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

    {recipients}

The mail system has been trying to deliver your message for {hours} hours.
It will not be retried further.

Error: {error}

--boundary-{bounce_id}
Content-Type: message/delivery-status

Reporting-MTA: dns; {hostname}
Arrival-Date: {arrival_date}

Final-Recipient: rfc822; {recipients}
Action: failed
Status: 5.0.0
Diagnostic-Code: smtp; {error}

--boundary-{bounce_id}
Content-Type: message/rfc822
Content-Description: Original message headers

{original_headers}
--boundary-{bounce_id}--
"#,
        hostname = hostname,
        sender = queued.mail_from,
        date = date,
        bounce_id = bounce_id,
        recipients = recipients_list,
        hours = MAX_RETRY_DURATION_HOURS,
        error = queued.last_error,
        arrival_date = queued.queued_at.format("%a, %d %b %Y %H:%M:%S %z"),
        original_headers = extract_headers(&original_data),
    );

    MailTransaction {
        mail_from: format!("mailer-daemon@{}", hostname),
        rcpt_to: vec![queued.mail_from.clone()],
        data: body.into_bytes(),
        is_outbound: false, // This is delivered locally
        authenticated_user: None,
    }
}

/// Extract just the headers from an email
fn extract_headers(email: &str) -> String {
    let mut headers = String::new();
    for line in email.lines() {
        if line.is_empty() {
            break; // Headers end at first blank line
        }
        headers.push_str(line);
        headers.push_str("\r\n");
    }
    headers
}

/// Shared outbox type for use across tasks
pub type SharedOutbox = Arc<RwLock<Outbox>>;

/// Create a shared outbox instance
pub fn create_shared_outbox() -> SharedOutbox {
    Arc::new(RwLock::new(Outbox::new()))
}
