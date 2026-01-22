use crate::client::smtp::MailTransaction;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

/// IMAP message flags
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MessageFlags {
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub deleted: bool,
    pub draft: bool,
}

impl MessageFlags {
    /// Convert flags to IMAP flag string (e.g., "(\Seen \Answered)")
    pub fn to_imap_string(&self) -> String {
        let mut flags = Vec::new();
        if self.seen {
            flags.push("\\Seen");
        }
        if self.answered {
            flags.push("\\Answered");
        }
        if self.flagged {
            flags.push("\\Flagged");
        }
        if self.deleted {
            flags.push("\\Deleted");
        }
        if self.draft {
            flags.push("\\Draft");
        }
        format!("({})", flags.join(" "))
    }

    /// Parse IMAP flags from string like "(\Seen \Flagged)"
    pub fn from_imap_string(s: &str) -> Self {
        let s_upper = s.to_uppercase();
        Self {
            seen: s_upper.contains("\\SEEN"),
            answered: s_upper.contains("\\ANSWERED"),
            flagged: s_upper.contains("\\FLAGGED"),
            deleted: s_upper.contains("\\DELETED"),
            draft: s_upper.contains("\\DRAFT"),
        }
    }
}

/// Stored email metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEmail {
    pub id: String,
    pub uid: u32,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub received_at: DateTime<Utc>,
    pub size: usize,
    #[serde(default)]
    pub flags: MessageFlags,
}

/// Mailbox information for IMAP
#[derive(Debug, Clone)]
pub struct MailboxInfo {
    pub email: String,
    pub messages: u32,
    pub recent: u32,
    pub unseen: u32,
    pub uid_validity: u32,
    pub uid_next: u32,
}

/// Email storage manager with per-user mailbox support
/// 
/// Directory structure:
/// storage/
///   mailboxes/
///     user@example.com/
///       mailbox.json       (mailbox metadata: uidvalidity, uidnext)
///       messages/
///         <uuid>.json      (message metadata)
///         <uuid>.eml       (raw email)
pub struct EmailStorage {
    storage_path: PathBuf,
}

impl EmailStorage {
    pub fn new(storage_path: &Path) -> Self {
        Self {
            storage_path: storage_path.to_path_buf(),
        }
    }

    /// Get the mailboxes directory
    fn mailboxes_dir(&self) -> PathBuf {
        self.storage_path.join("mailboxes")
    }

    /// Get the directory for a specific user's mailbox
    fn user_mailbox_dir(&self, email: &str) -> PathBuf {
        let email_safe = email.to_lowercase().replace(['/', '\\', ':'], "_");
        self.mailboxes_dir().join(&email_safe)
    }

    /// Get the messages directory for a user
    fn user_messages_dir(&self, email: &str) -> PathBuf {
        self.user_mailbox_dir(email).join("messages")
    }

    /// Mailbox metadata file
    fn mailbox_meta_path(&self, email: &str) -> PathBuf {
        self.user_mailbox_dir(email).join("mailbox.json")
    }

    /// Get or create mailbox metadata
    async fn get_or_create_mailbox_meta(
        &self,
        email: &str,
    ) -> Result<MailboxMeta, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.mailbox_meta_path(email);
        
        if path.exists() {
            let data = fs::read_to_string(&path).await?;
            Ok(serde_json::from_str(&data)?)
        } else {
            let meta = MailboxMeta {
                uid_validity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32,
                uid_next: 1,
            };
            self.save_mailbox_meta(email, &meta).await?;
            Ok(meta)
        }
    }

    /// Save mailbox metadata
    async fn save_mailbox_meta(
        &self,
        email: &str,
        meta: &MailboxMeta,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mailbox_dir = self.user_mailbox_dir(email);
        fs::create_dir_all(&mailbox_dir).await?;
        
        let path = self.mailbox_meta_path(email);
        let data = serde_json::to_string_pretty(meta)?;
        fs::write(&path, data).await?;
        Ok(())
    }

    /// Allocate the next UID for a mailbox
    async fn allocate_uid(
        &self,
        email: &str,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let mut meta = self.get_or_create_mailbox_meta(email).await?;
        let uid = meta.uid_next;
        meta.uid_next += 1;
        self.save_mailbox_meta(email, &meta).await?;
        Ok(uid)
    }

    /// Store a received email, delivering to each recipient's mailbox
    pub async fn store_email(
        &self,
        transaction: &MailTransaction,
    ) -> Result<Vec<StoredEmail>, Box<dyn std::error::Error + Send + Sync>> {
        let mut stored = Vec::new();

        // Deliver to each recipient
        for rcpt in &transaction.rcpt_to {
            let email_lower = rcpt.to_lowercase();
            let messages_dir = self.user_messages_dir(&email_lower);
            fs::create_dir_all(&messages_dir).await?;

            // Generate unique ID and allocate UID
            let id = Uuid::new_v4().to_string();
            let uid = self.allocate_uid(&email_lower).await?;
            let received_at = Utc::now();

            // Create metadata
            let metadata = StoredEmail {
                id: id.clone(),
                uid,
                mail_from: transaction.mail_from.clone(),
                rcpt_to: vec![rcpt.clone()],
                received_at,
                size: transaction.data.len(),
                flags: MessageFlags::default(),
            };

            // Save metadata
            let metadata_path = messages_dir.join(format!("{}.json", id));
            let metadata_json = serde_json::to_string_pretty(&metadata)?;
            fs::write(&metadata_path, metadata_json).await?;

            // Save raw email data
            let data_path = messages_dir.join(format!("{}.eml", id));
            fs::write(&data_path, &transaction.data).await?;

            println!(
                "Email stored: id={} uid={} mailbox={} from={} size={}",
                id, uid, email_lower, metadata.mail_from, metadata.size
            );

            stored.push(metadata);
        }

        Ok(stored)
    }

    /// Get mailbox info for IMAP SELECT
    pub async fn get_mailbox_info(
        &self,
        email: &str,
    ) -> Result<MailboxInfo, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let meta = self.get_or_create_mailbox_meta(&email_lower).await?;
        let messages = self.list_messages(&email_lower).await?;

        let total = messages.len() as u32;
        let unseen = messages.iter().filter(|m| !m.flags.seen).count() as u32;

        Ok(MailboxInfo {
            email: email_lower,
            messages: total,
            recent: 0, // We don't track recent separately for simplicity
            unseen,
            uid_validity: meta.uid_validity,
            uid_next: meta.uid_next,
        })
    }

    /// List all messages in a user's mailbox
    pub async fn list_messages(
        &self,
        email: &str,
    ) -> Result<Vec<StoredEmail>, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let messages_dir = self.user_messages_dir(&email_lower);

        if !messages_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let mut entries = fs::read_dir(&messages_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let data = fs::read_to_string(&path).await?;
                if let Ok(metadata) = serde_json::from_str::<StoredEmail>(&data) {
                    messages.push(metadata);
                }
            }
        }

        // Sort by UID (oldest first)
        messages.sort_by_key(|m| m.uid);

        Ok(messages)
    }

    /// Get message by UID
    pub async fn get_message_by_uid(
        &self,
        email: &str,
        uid: u32,
    ) -> Result<Option<(StoredEmail, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
        let messages = self.list_messages(email).await?;
        
        if let Some(msg) = messages.into_iter().find(|m| m.uid == uid) {
            let messages_dir = self.user_messages_dir(email);
            let data_path = messages_dir.join(format!("{}.eml", msg.id));
            let data = fs::read(&data_path).await?;
            Ok(Some((msg, data)))
        } else {
            Ok(None)
        }
    }

    /// Get message by sequence number (1-based index in sorted UID order)
    pub async fn get_message_by_seq(
        &self,
        email: &str,
        seq: u32,
    ) -> Result<Option<(StoredEmail, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
        let messages = self.list_messages(email).await?;
        
        if seq > 0 && (seq as usize) <= messages.len() {
            let msg = &messages[(seq - 1) as usize];
            let messages_dir = self.user_messages_dir(email);
            let data_path = messages_dir.join(format!("{}.eml", msg.id));
            let data = fs::read(&data_path).await?;
            Ok(Some((msg.clone(), data)))
        } else {
            Ok(None)
        }
    }

    /// Update message flags
    pub async fn update_flags(
        &self,
        email: &str,
        uid: u32,
        flags: MessageFlags,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let messages_dir = self.user_messages_dir(&email_lower);
        let messages = self.list_messages(&email_lower).await?;

        if let Some(mut msg) = messages.into_iter().find(|m| m.uid == uid) {
            msg.flags = flags;
            let metadata_path = messages_dir.join(format!("{}.json", msg.id));
            let metadata_json = serde_json::to_string_pretty(&msg)?;
            fs::write(&metadata_path, metadata_json).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete messages marked with \Deleted flag (EXPUNGE)
    pub async fn expunge(
        &self,
        email: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let messages_dir = self.user_messages_dir(&email_lower);
        let messages = self.list_messages(&email_lower).await?;

        let mut expunged = Vec::new();

        for msg in messages {
            if msg.flags.deleted {
                let metadata_path = messages_dir.join(format!("{}.json", msg.id));
                let data_path = messages_dir.join(format!("{}.eml", msg.id));
                
                let _ = fs::remove_file(&metadata_path).await;
                let _ = fs::remove_file(&data_path).await;
                
                expunged.push(msg.uid);
            }
        }

        Ok(expunged)
    }

    // ==================== Synchronous Methods ====================
    // These are for use in synchronous contexts like IMAP handlers
    
    /// Synchronously get message content by UID
    pub fn get_message_by_uid_sync(
        &self,
        email: &str,
        uid: u32,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let messages_dir = self.user_messages_dir(email);
        if !messages_dir.exists() {
            return Ok(None);
        }

        // Read all json files to find the one with matching UID
        for entry in std::fs::read_dir(&messages_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let data = std::fs::read_to_string(&path)?;
                if let Ok(metadata) = serde_json::from_str::<StoredEmail>(&data) {
                    if metadata.uid == uid {
                        let eml_path = messages_dir.join(format!("{}.eml", metadata.id));
                        let content = std::fs::read(&eml_path)?;
                        return Ok(Some(content));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Synchronously list all messages in a user's mailbox
    pub fn list_messages_sync(
        &self,
        email: &str,
    ) -> Result<Vec<StoredEmail>, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let messages_dir = self.user_messages_dir(&email_lower);

        if !messages_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        for entry in std::fs::read_dir(&messages_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let data = std::fs::read_to_string(&path)?;
                if let Ok(metadata) = serde_json::from_str::<StoredEmail>(&data) {
                    messages.push(metadata);
                }
            }
        }

        // Sort by UID (oldest first)
        messages.sort_by_key(|m| m.uid);

        Ok(messages)
    }

    /// Synchronously get mailbox info for IMAP SELECT
    pub fn get_mailbox_info_sync(
        &self,
        email: &str,
    ) -> Result<MailboxInfo, Box<dyn std::error::Error + Send + Sync>> {
        let email_lower = email.to_lowercase();
        let meta = self.get_or_create_mailbox_meta_sync(&email_lower)?;
        let messages = self.list_messages_sync(&email_lower)?;

        let total = messages.len() as u32;
        let unseen = messages.iter().filter(|m| !m.flags.seen).count() as u32;

        Ok(MailboxInfo {
            email: email_lower,
            messages: total,
            recent: 0,
            unseen,
            uid_validity: meta.uid_validity,
            uid_next: meta.uid_next,
        })
    }

    /// Synchronously get or create mailbox metadata
    fn get_or_create_mailbox_meta_sync(
        &self,
        email: &str,
    ) -> Result<MailboxMeta, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.mailbox_meta_path(email);
        
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let meta: MailboxMeta = serde_json::from_str(&data)?;
            Ok(meta)
        } else {
            // Create new mailbox meta
            let meta = MailboxMeta {
                uid_validity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(1),
                uid_next: 1,
            };
            // Ensure directory exists
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let data = serde_json::to_string_pretty(&meta)?;
            std::fs::write(&path, data)?;
            Ok(meta)
        }
    }

    /// Synchronously update message flags
    pub fn update_flags_sync(
        &self,
        email: &str,
        uid: u32,
        flags: MessageFlags,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let messages_dir = self.user_messages_dir(email);
        
        for entry in std::fs::read_dir(&messages_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let data = std::fs::read_to_string(&path)?;
                if let Ok(mut metadata) = serde_json::from_str::<StoredEmail>(&data) {
                    if metadata.uid == uid {
                        metadata.flags = flags;
                        let updated_data = serde_json::to_string_pretty(&metadata)?;
                        std::fs::write(&path, updated_data)?;
                        return Ok(());
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Synchronously expunge deleted messages
    pub fn expunge_sync(
        &self,
        email: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let messages = self.list_messages_sync(email)?;
        let messages_dir = self.user_messages_dir(email);
        let mut expunged = Vec::new();

        for msg in messages {
            if msg.flags.deleted {
                let metadata_path = messages_dir.join(format!("{}.json", msg.id));
                let data_path = messages_dir.join(format!("{}.eml", msg.id));
                
                let _ = std::fs::remove_file(&metadata_path);
                let _ = std::fs::remove_file(&data_path);
                
                expunged.push(msg.uid);
            }
        }

        Ok(expunged)
    }

    // Legacy method for backwards compatibility (list all emails across all mailboxes)
    pub async fn list_emails(&self) -> Result<Vec<StoredEmail>, Box<dyn std::error::Error + Send + Sync>> {
        let mailboxes_dir = self.mailboxes_dir();
        
        if !mailboxes_dir.exists() {
            return Ok(Vec::new());
        }

        let mut all_emails = Vec::new();
        let mut entries = fs::read_dir(&mailboxes_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(email) = path.file_name().and_then(|n| n.to_str()) {
                    let messages = self.list_messages(email).await?;
                    all_emails.extend(messages);
                }
            }
        }

        // Sort by received time, newest first
        all_emails.sort_by(|a, b| b.received_at.cmp(&a.received_at));

        Ok(all_emails)
    }
}

/// Mailbox metadata stored in mailbox.json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxMeta {
    uid_validity: u32,
    uid_next: u32,
}
