use crate::client::dns::{dane_tlsa_record, CloudflareClient, DnsRecordType};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::fs;

const TLSA_TTL: u32 = 3600;
const ROLLOVER_WAIT: Duration = Duration::from_secs(TLSA_TTL as u64 * 2);

/// State of a DANE rollover operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloverState {
    pub hostname: String,
    pub old_hash: String,
    pub new_hash: String,
    pub started_at: u64, // Unix timestamp
    pub completed: bool,
}

impl RolloverState {
    /// Check if enough time has passed to complete the rollover
    pub fn can_complete(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.started_at >= ROLLOVER_WAIT.as_secs()
    }
}

/// Manages DANE TLSA records with rollover support
pub struct DaneManager {
    storage_path: std::path::PathBuf,
    rollover: Option<RolloverState>,
}

impl DaneManager {
    pub fn new(storage_path: &Path) -> Self {
        Self {
            storage_path: storage_path.to_path_buf(),
            rollover: None,
        }
    }

    /// Load rollover state from storage
    pub async fn load(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = self.storage_path.join("dane_rollover.json");
        if path.exists() {
            let data = fs::read_to_string(&path).await?;
            self.rollover = Some(serde_json::from_str(&data)?);
            println!("Loaded DANE rollover state");
        }
        Ok(())
    }

    /// Save rollover state to storage
    async fn save(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = self.storage_path.join("dane_rollover.json");
        if let Some(ref rollover) = self.rollover {
            let data = serde_json::to_string_pretty(rollover)?;
            fs::write(&path, data).await?;
        } else {
            // Remove file if no rollover in progress
            if path.exists() {
                fs::remove_file(&path).await?;
            }
        }
        Ok(())
    }

    /// Set initial DANE record (no rollover needed)
    pub async fn set_initial_record(
        &mut self,
        hostname: &str,
        pubkey_hash: &str,
        dns_client: &CloudflareClient,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let record = dane_tlsa_record(hostname, pubkey_hash);
        dns_client.upsert_record(&record).await?;
        println!("Set initial DANE TLSA record for {}", hostname);
        Ok(())
    }

    /// Start a DANE rollover (add new record alongside old)
    pub async fn start_rollover(
        &mut self,
        hostname: &str,
        old_hash: &str,
        new_hash: &str,
        dns_client: &CloudflareClient,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("Starting DANE rollover for {}", hostname);

        // Add new TLSA record (old one stays)
        let new_record = dane_tlsa_record(hostname, new_hash);
        dns_client.create_record(&new_record).await?;

        // Save rollover state
        let state = RolloverState {
            hostname: hostname.to_string(),
            old_hash: old_hash.to_string(),
            new_hash: new_hash.to_string(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            completed: false,
        };

        self.rollover = Some(state);
        self.save().await?;

        println!(
            "DANE rollover started. New record added. Will complete after {} seconds",
            ROLLOVER_WAIT.as_secs()
        );

        Ok(())
    }

    /// Check and complete rollover if enough time has passed
    pub async fn check_and_complete_rollover(
        &mut self,
        dns_client: &CloudflareClient,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let rollover = match &self.rollover {
            Some(r) if !r.completed && r.can_complete() => r.clone(),
            _ => return Ok(false),
        };

        println!("Completing DANE rollover for {}", rollover.hostname);

        // Find and delete old TLSA record
        let tlsa_name = format!("_25._tcp.{}", rollover.hostname);
        let records = dns_client
            .find_records(&tlsa_name, &DnsRecordType::TLSA)
            .await?;

        for (record_id, content) in records {
            // Check if this is the old record (contains old hash)
            if content.contains(&rollover.old_hash) {
                dns_client.delete_record(&record_id).await?;
                println!("Deleted old DANE TLSA record");
            }
        }

        // Clear rollover state
        self.rollover = None;
        self.save().await?;

        println!("DANE rollover completed for {}", rollover.hostname);
        Ok(true)
    }

    /// Get the current hash that should be used for connections
    /// During rollover, this returns the NEW hash (we use new cert)
    pub fn current_hash(&self) -> Option<&str> {
        self.rollover.as_ref().map(|r| r.new_hash.as_str())
    }

    /// Check if rollover is in progress
    pub fn is_rollover_in_progress(&self) -> bool {
        self.rollover.as_ref().map(|r| !r.completed).unwrap_or(false)
    }
}
