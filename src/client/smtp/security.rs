/// Outbound email security policies
/// 
/// Implements MTA-STS (RFC 8461) and DANE (RFC 7672) verification
/// for outbound email connections.

use hickory_resolver::TokioResolver;
use reqwest::Client;
use sha2::{Sha256, Sha512, Digest};
use std::collections::HashSet;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Security policy for a domain
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Whether TLS is required
    pub require_tls: bool,
    /// Valid MX hostnames (from MTA-STS)
    pub valid_mx_hosts: Option<HashSet<String>>,
    /// DANE TLSA records for certificate verification
    pub tlsa_records: Vec<TlsaRecord>,
    /// Whether DANE records were DNSSEC-validated
    pub dane_validated: bool,
    /// Source of the policy
    pub source: PolicySource,
}

#[derive(Debug, Clone)]
pub enum PolicySource {
    None,
    MtaSts,
    Dane,
    Both,
}

impl SecurityPolicy {
    pub fn none() -> Self {
        Self {
            require_tls: false,
            valid_mx_hosts: None,
            tlsa_records: Vec::new(),
            dane_validated: false,
            source: PolicySource::None,
        }
    }
}

/// DANE TLSA record
#[derive(Debug, Clone)]
pub struct TlsaRecord {
    /// Certificate usage (0-3)
    pub usage: u8,
    /// Selector (0=full cert, 1=SPKI)
    pub selector: u8,
    /// Matching type (0=exact, 1=SHA-256, 2=SHA-512)
    pub matching_type: u8,
    /// Certificate association data
    pub data: Vec<u8>,
}

impl TlsaRecord {
    /// Parse from DNS record data (hex string format commonly returned)
    pub fn from_rdata(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            usage: data[0],
            selector: data[1],
            matching_type: data[2],
            data: data[3..].to_vec(),
        })
    }
    
    /// Parse from hex string (e.g., "3 1 1 abc123...")
    pub fn from_text(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }
        
        let usage = parts[0].parse().ok()?;
        let selector = parts[1].parse().ok()?;
        let matching_type = parts[2].parse().ok()?;
        let hex_data = parts[3..].join("");
        let data = hex::decode(&hex_data).ok()?;
        
        Some(Self {
            usage,
            selector,
            matching_type,
            data,
        })
    }
    
    /// Verify a certificate chain against this TLSA record
    pub fn verify_certificate(&self, cert_chain: &[CertificateDer]) -> bool {
        if cert_chain.is_empty() {
            return false;
        }
        
        // Determine which certificate to check based on usage
        let cert = match self.usage {
            // PKIX-TA (0) or DANE-TA (2): Trust anchor (CA cert)
            0 | 2 => cert_chain.last(),
            // PKIX-EE (1) or DANE-EE (3): End entity (server cert)
            1 | 3 => cert_chain.first(),
            _ => return false,
        };
        
        let cert = match cert {
            Some(c) => c,
            None => return false,
        };
        
        // Get the data to hash based on selector
        let data_to_hash = match self.selector {
            0 => cert.as_ref().to_vec(), // Full certificate
            1 => {
                // SubjectPublicKeyInfo - need to extract from certificate
                match extract_spki(cert.as_ref()) {
                    Some(spki) => spki,
                    None => return false,
                }
            }
            _ => return false,
        };
        
        // Compare based on matching type
        match self.matching_type {
            0 => data_to_hash == self.data, // Exact match
            1 => {
                // SHA-256
                let hash = Sha256::digest(&data_to_hash);
                hash.as_slice() == self.data.as_slice()
            }
            2 => {
                // SHA-512
                let hash = Sha512::digest(&data_to_hash);
                hash.as_slice() == self.data.as_slice()
            }
            _ => false,
        }
    }
}

/// Extract SubjectPublicKeyInfo from a DER-encoded certificate
fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    // X.509 certificate structure:
    // SEQUENCE {
    //   tbsCertificate SEQUENCE {
    //     version [0] EXPLICIT ...
    //     serialNumber INTEGER
    //     signature AlgorithmIdentifier
    //     issuer Name
    //     validity Validity
    //     subject Name
    //     subjectPublicKeyInfo SubjectPublicKeyInfo  <-- we want this
    //     ...
    //   }
    //   ...
    // }
    
    // Simple ASN.1 DER parser for this specific case
    use x509_parser::prelude::*;
    
    match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => {
            Some(cert.public_key().raw.to_vec())
        }
        Err(_) => None,
    }
}

/// MTA-STS policy fetcher
pub struct MtaStsClient {
    http_client: Client,
}

impl MtaStsClient {
    pub fn new() -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        
        Self { http_client }
    }
    
    /// Fetch MTA-STS policy for a domain
    pub async fn fetch_policy(&self, domain: &str) -> Option<MtaStsPolicy> {
        // First check for _mta-sts DNS TXT record
        let resolver = match TokioResolver::builder_tokio() {
            Ok(builder) => builder.build(),
            Err(_) => return None,
        };
        
        let sts_domain = format!("_mta-sts.{}", domain);
        let txt_lookup = resolver.txt_lookup(&sts_domain).await.ok()?;
        
        let mut has_sts_record = false;
        for txt in txt_lookup.iter() {
            let data = txt.to_string();
            if data.starts_with("v=STSv1") {
                has_sts_record = true;
                break;
            }
        }
        
        if !has_sts_record {
            return None;
        }
        
        // Fetch the policy file
        let policy_url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
        let response = self.http_client.get(&policy_url).send().await.ok()?;
        
        if !response.status().is_success() {
            return None;
        }
        
        let policy_text = response.text().await.ok()?;
        MtaStsPolicy::parse(&policy_text)
    }
}

/// Parsed MTA-STS policy
#[derive(Debug, Clone)]
pub struct MtaStsPolicy {
    pub version: String,
    pub mode: MtaStsMode,
    pub mx_hosts: HashSet<String>,
    pub max_age: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

impl MtaStsPolicy {
    fn parse(text: &str) -> Option<Self> {
        let mut version = None;
        let mut mode = MtaStsMode::None;
        let mut mx_hosts = HashSet::new();
        let mut max_age = 0u64;
        
        for line in text.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                
                match key.as_str() {
                    "version" => version = Some(value.to_string()),
                    "mode" => {
                        mode = match value.to_lowercase().as_str() {
                            "enforce" => MtaStsMode::Enforce,
                            "testing" => MtaStsMode::Testing,
                            _ => MtaStsMode::None,
                        };
                    }
                    "mx" => {
                        mx_hosts.insert(value.to_lowercase());
                    }
                    "max_age" => {
                        max_age = value.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }
        
        let version = version?;
        if version != "STSv1" {
            return None;
        }
        
        Some(Self {
            version,
            mode,
            mx_hosts,
            max_age,
        })
    }
    
    /// Check if an MX hostname is valid according to this policy
    pub fn is_valid_mx(&self, mx_host: &str) -> bool {
        let mx_lower = mx_host.to_lowercase();
        
        for allowed in &self.mx_hosts {
            if allowed.starts_with("*.") {
                // Wildcard match
                let suffix = &allowed[1..]; // ".example.com"
                if mx_lower.ends_with(suffix) || mx_lower == allowed[2..] {
                    return true;
                }
            } else if mx_lower == *allowed {
                return true;
            }
        }
        
        false
    }
}

/// DANE TLSA record fetcher with DNSSEC validation
pub struct DaneClient {
    resolver: TokioResolver,
}

/// Result of a TLSA lookup
pub struct TlsaLookupResult {
    /// The TLSA records found
    pub records: Vec<TlsaRecord>,
    /// Whether the records were DNSSEC-validated (required for DANE security)
    pub dnssec_validated: bool,
}

impl DaneClient {
    pub fn new() -> Result<Self, String> {
        use hickory_resolver::config::ResolverOpts;
        
        // Configure resolver with DNSSEC validation enabled
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enable DNSSEC validation
        
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| format!("Failed to create resolver builder: {}", e))?
            .with_options(opts)
            .build();
        
        Ok(Self { resolver })
    }
    
    /// Lookup TLSA records for a host/port with DNSSEC validation
    pub async fn lookup_tlsa(&self, hostname: &str, port: u16) -> TlsaLookupResult {
        // TLSA record name: _port._tcp.hostname
        let tlsa_name = format!("_{}._tcp.{}", port, hostname);
        
        let mut records = Vec::new();
        let mut dnssec_validated = false;
        
        // Try TLSA lookup with DNSSEC validation
        match self.resolver.tlsa_lookup(&tlsa_name).await {
            Ok(lookup) => {
                // Use the DNSSEC-aware iterator which returns Proven<> wrappers
                // If DNSSEC validation is enabled and records are signed, this will
                // only return validated records
                let lookup_ref = lookup.as_lookup();
                
                // Check if we're actually validating DNSSEC by inspecting the records
                // The resolver with validate=true will fail the lookup if DNSSEC 
                // validation fails, so if we get here, records are either:
                // 1. DNSSEC-validated (if the zone is signed)
                // 2. From an unsigned zone (no DNSSEC to validate)
                // 
                // For DANE security, we should only trust TLSA records from DNSSEC-signed zones.
                // We check for RRSIG records to determine if the response was signed.
                let has_rrsig = lookup_ref.record_iter()
                    .any(|r| r.record_type() == hickory_resolver::proto::rr::RecordType::RRSIG);
                
                if has_rrsig {
                    dnssec_validated = true;
                    println!("      DANE: TLSA records are DNSSEC-validated");
                } else {
                    println!("      DANE: WARNING - TLSA records NOT DNSSEC-signed");
                    println!("      DANE: Records will be IGNORED for security");
                    // Return empty - unsigned TLSA records are insecure
                    return TlsaLookupResult {
                        records: Vec::new(),
                        dnssec_validated: false,
                    };
                }
                
                // Parse TLSA records
                for tlsa_data in lookup.iter() {
                    let tlsa = TlsaRecord {
                        usage: tlsa_data.cert_usage().into(),
                        selector: tlsa_data.selector().into(),
                        matching_type: tlsa_data.matching().into(),
                        data: tlsa_data.cert_data().to_vec(),
                    };
                    records.push(tlsa);
                }
            }
            Err(e) => {
                // TLSA lookup failed - this is normal if DANE is not configured
                // or if DNSSEC validation failed
                let err_str = e.to_string();
                if err_str.contains("DNSSEC") || err_str.contains("dnssec") {
                    eprintln!("      DANE: DNSSEC validation FAILED for {}: {}", tlsa_name, e);
                } else {
                    eprintln!("      DANE: No TLSA records for {}: {}", tlsa_name, e);
                }
            }
        }
        
        TlsaLookupResult {
            records,
            dnssec_validated,
        }
    }
}

/// Combined security policy checker
pub struct OutboundSecurityChecker {
    mta_sts_client: MtaStsClient,
    dane_client: Option<DaneClient>,
}

impl OutboundSecurityChecker {
    pub fn new() -> Self {
        Self {
            mta_sts_client: MtaStsClient::new(),
            dane_client: DaneClient::new().ok(),
        }
    }
    
    /// Get the security policy for a domain
    pub async fn get_policy(&self, domain: &str, mx_host: &str, port: u16) -> SecurityPolicy {
        let mut policy = SecurityPolicy::none();
        
        // Check MTA-STS
        println!("      Checking MTA-STS for {}...", domain);
        if let Some(mta_sts) = self.mta_sts_client.fetch_policy(domain).await {
            println!("      MTA-STS: Found policy (mode={:?})", mta_sts.mode);
            
            if mta_sts.mode == MtaStsMode::Enforce {
                policy.require_tls = true;
                policy.valid_mx_hosts = Some(mta_sts.mx_hosts.clone());
                policy.source = PolicySource::MtaSts;
                
                // Verify the MX host is allowed
                if !mta_sts.is_valid_mx(mx_host) {
                    println!("      MTA-STS: WARNING - MX host {} not in policy!", mx_host);
                }
            }
        } else {
            println!("      MTA-STS: No policy found");
        }
        
        // Check DANE
        if let Some(ref dane_client) = self.dane_client {
            println!("      Checking DANE for {}:{}...", mx_host, port);
            let tlsa_result = dane_client.lookup_tlsa(mx_host, port).await;
            
            if !tlsa_result.records.is_empty() {
                println!("      DANE: Found {} TLSA record(s), DNSSEC validated: {}", 
                         tlsa_result.records.len(), tlsa_result.dnssec_validated);
                policy.require_tls = true;
                policy.tlsa_records = tlsa_result.records;
                policy.dane_validated = tlsa_result.dnssec_validated;
                policy.source = match policy.source {
                    PolicySource::MtaSts => PolicySource::Both,
                    _ => PolicySource::Dane,
                };
            } else {
                println!("      DANE: No TLSA records (or DNSSEC validation failed)");
            }
        }
        
        policy
    }
    
    /// Verify a certificate chain against DANE TLSA records
    pub fn verify_dane(&self, policy: &SecurityPolicy, cert_chain: &[CertificateDer]) -> bool {
        if policy.tlsa_records.is_empty() {
            return true; // No DANE records = no DANE verification needed
        }
        
        // DANE requires DNSSEC validation for security
        if !policy.dane_validated {
            println!("      DANE: WARNING - TLSA records not DNSSEC-validated, skipping verification");
            return true; // Don't enforce unvalidated DANE
        }
        
        // At least one TLSA record must match
        for tlsa in &policy.tlsa_records {
            if tlsa.verify_certificate(cert_chain) {
                println!("      DANE: Certificate verified against DNSSEC-validated TLSA record");
                return true;
            }
        }
        
        println!("      DANE: Certificate verification FAILED");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mta_sts_policy_parse() {
        let policy_text = "version: STSv1\r\n\
                          mode: enforce\r\n\
                          mx: mail.example.com\r\n\
                          mx: *.example.com\r\n\
                          max_age: 604800\r\n";
        
        let policy = MtaStsPolicy::parse(policy_text).unwrap();
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert!(policy.mx_hosts.contains("mail.example.com"));
        assert!(policy.mx_hosts.contains("*.example.com"));
        assert_eq!(policy.max_age, 604800);
    }
    
    #[test]
    fn test_mta_sts_mx_validation() {
        let policy_text = "version: STSv1\r\n\
                          mode: enforce\r\n\
                          mx: mail.example.com\r\n\
                          mx: *.mail.example.com\r\n\
                          max_age: 604800\r\n";
        
        let policy = MtaStsPolicy::parse(policy_text).unwrap();
        
        assert!(policy.is_valid_mx("mail.example.com"));
        assert!(policy.is_valid_mx("mx1.mail.example.com"));
        assert!(!policy.is_valid_mx("other.example.com"));
    }
    
    #[test]
    fn test_tlsa_parse() {
        let tlsa = TlsaRecord::from_text("3 1 1 abc123def456").unwrap();
        assert_eq!(tlsa.usage, 3);
        assert_eq!(tlsa.selector, 1);
        assert_eq!(tlsa.matching_type, 1);
    }
}
