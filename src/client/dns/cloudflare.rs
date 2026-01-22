use super::records::{DnsRecord, DnsRecordType};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare API client for DNS management
pub struct CloudflareClient {
    client: Client,
    api_token: String,
    zone_id: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    proxied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<RecordData>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RecordData {
    Tlsa(TlsaData),
    Caa(CaaData),
}

#[derive(Debug, Serialize)]
struct TlsaData {
    usage: u8,
    selector: u8,
    matching_type: u8,
    certificate: String,
}

#[derive(Debug, Serialize)]
struct CaaData {
    flags: u8,
    tag: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

/// Error from Cloudflare API
#[derive(Debug, Deserialize, Clone)]
pub struct CloudflareError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct ListRecordsResult {
    id: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    record_type: String,
    #[allow(dead_code)]
    name: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct RecordResult {
    id: String,
}

impl CloudflareClient {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
        }
    }

    /// Create or update a DNS record
    pub async fn upsert_record(&self, record: &DnsRecord) -> Result<String, CloudflareError> {
        // First, try to find existing record
        if let Some(existing_id) = self.find_record(&record.name, &record.record_type).await? {
            // Update existing record
            self.update_record(&existing_id, record).await
        } else {
            // Create new record
            self.create_record(record).await
        }
    }

    /// Parse record content into structured data for Cloudflare API
    fn parse_record_data(record: &DnsRecord) -> (String, Option<RecordData>) {
        match record.record_type {
            DnsRecordType::TLSA => {
                // Parse TLSA content: "usage selector matching_type hash"
                let parts: Vec<&str> = record.content.split_whitespace().collect();
                if parts.len() == 4 {
                    let data = RecordData::Tlsa(TlsaData {
                        usage: parts[0].parse().unwrap_or(3),
                        selector: parts[1].parse().unwrap_or(1),
                        matching_type: parts[2].parse().unwrap_or(1),
                        certificate: parts[3].to_string(),
                    });
                    (String::new(), Some(data))
                } else {
                    (record.content.clone(), None)
                }
            }
            DnsRecordType::CAA => {
                // Parse CAA content: "flags tag \"value\""
                let parts: Vec<&str> = record.content.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let flags: u8 = parts[0].parse().unwrap_or(0);
                    let tag = parts[1].to_string();
                    // Remove quotes from value
                    let value = parts[2].trim_matches('"').to_string();
                    let data = RecordData::Caa(CaaData { flags, tag, value });
                    (String::new(), Some(data))
                } else {
                    (record.content.clone(), None)
                }
            }
            _ => (record.content.clone(), None),
        }
    }

    /// Create a new DNS record
    pub async fn create_record(&self, record: &DnsRecord) -> Result<String, CloudflareError> {
        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_BASE, self.zone_id);

        let (content, data) = Self::parse_record_data(record);

        let request = CreateRecordRequest {
            record_type: record.record_type.as_str().to_string(),
            name: record.name.clone(),
            content,
            ttl: record.ttl,
            priority: record.priority,
            proxied: record.proxied,
            data,
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        let result: CloudflareResponse<RecordResult> =
            response.json().await.map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        if result.success {
            Ok(result.result.map(|r| r.id).unwrap_or_default())
        } else {
            Err(result.errors.into_iter().next().unwrap_or(CloudflareError {
                code: -1,
                message: "Unknown error".to_string(),
            }))
        }
    }

    /// Update an existing DNS record
    pub async fn update_record(
        &self,
        record_id: &str,
        record: &DnsRecord,
    ) -> Result<String, CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_BASE, self.zone_id, record_id
        );

        let (content, data) = Self::parse_record_data(record);

        let request = CreateRecordRequest {
            record_type: record.record_type.as_str().to_string(),
            name: record.name.clone(),
            content,
            ttl: record.ttl,
            priority: record.priority,
            proxied: record.proxied,
            data,
        };

        let response = self
            .client
            .put(&url)
            .bearer_auth(&self.api_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        let result: CloudflareResponse<RecordResult> =
            response.json().await.map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        if result.success {
            Ok(result.result.map(|r| r.id).unwrap_or_default())
        } else {
            Err(result.errors.into_iter().next().unwrap_or(CloudflareError {
                code: -1,
                message: "Unknown error".to_string(),
            }))
        }
    }

    /// Delete a DNS record by ID
    pub async fn delete_record(&self, record_id: &str) -> Result<(), CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_BASE, self.zone_id, record_id
        );

        let response = self
            .client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        let result: CloudflareResponse<()> =
            response.json().await.map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        if result.success {
            Ok(())
        } else {
            Err(result.errors.into_iter().next().unwrap_or(CloudflareError {
                code: -1,
                message: "Unknown error".to_string(),
            }))
        }
    }

    /// Find a record by name and type, returning its ID if found
    pub async fn find_record(
        &self,
        name: &str,
        record_type: &DnsRecordType,
    ) -> Result<Option<String>, CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records?name={}&type={}",
            CLOUDFLARE_API_BASE,
            self.zone_id,
            name,
            record_type.as_str()
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        let result: CloudflareResponse<Vec<ListRecordsResult>> =
            response.json().await.map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        if result.success {
            Ok(result.result.and_then(|records| records.into_iter().next().map(|r| r.id)))
        } else {
            Err(result.errors.into_iter().next().unwrap_or(CloudflareError {
                code: -1,
                message: "Unknown error".to_string(),
            }))
        }
    }

    /// Find all records matching a name and type
    pub async fn find_records(
        &self,
        name: &str,
        record_type: &DnsRecordType,
    ) -> Result<Vec<(String, String)>, CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records?name={}&type={}",
            CLOUDFLARE_API_BASE,
            self.zone_id,
            name,
            record_type.as_str()
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        let result: CloudflareResponse<Vec<ListRecordsResult>> =
            response.json().await.map_err(|e| CloudflareError {
                code: -1,
                message: e.to_string(),
            })?;

        if result.success {
            Ok(result
                .result
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.id, r.content))
                .collect())
        } else {
            Err(result.errors.into_iter().next().unwrap_or(CloudflareError {
                code: -1,
                message: "Unknown error".to_string(),
            }))
        }
    }

    /// Get the content of a record by name and type
    pub async fn get_record_content(
        &self,
        name: &str,
        record_type: &DnsRecordType,
    ) -> Result<Option<String>, CloudflareError> {
        let records = self.find_records(name, record_type).await?;
        Ok(records.into_iter().next().map(|(_, content)| content))
    }

    /// Check if a record already has the expected content
    pub async fn record_matches(
        &self,
        record: &DnsRecord,
    ) -> Result<bool, CloudflareError> {
        let current = self.get_record_content(&record.name, &record.record_type).await?;
        
        match current {
            Some(current_content) => {
                // For TXT records, Cloudflare may split long records and add internal quotes/spaces
                // Normalize by removing all quotes and whitespace for comparison
                let normalize_txt = |s: &str| -> String {
                    s.chars().filter(|c| *c != '"' && !c.is_whitespace()).collect()
                };
                
                if record.record_type == DnsRecordType::TXT {
                    let current_normalized = normalize_txt(&current_content);
                    let expected_normalized = normalize_txt(&record.content);
                    Ok(current_normalized == expected_normalized)
                } else {
                    Ok(current_content == record.content)
                }
            }
            None => Ok(false),
        }
    }

    /// Create or update a record only if it differs from the current value
    pub async fn upsert_record_if_changed(&self, record: &DnsRecord) -> Result<(String, bool), CloudflareError> {
        // Check if the record already has the correct content
        if self.record_matches(record).await? {
            // Record already correct, no update needed
            if let Some(id) = self.find_record(&record.name, &record.record_type).await? {
                return Ok((id, false)); // false = not changed
            }
        }
        
        // Record differs or doesn't exist, upsert it
        let id = self.upsert_record(record).await?;
        Ok((id, true)) // true = changed
    }
}

impl std::fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cloudflare error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for CloudflareError {}
