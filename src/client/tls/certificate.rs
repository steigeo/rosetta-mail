use ::pem::{parse as pem_parse, parse_many as pem_parse_many};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;
use x509_parser::prelude::*;

use crate::client::dns::CloudflareClient;
use crate::client::tls::acme::AcmeClient;
use crate::client::tls::dane::DaneManager;

/// Certificate and key stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: i64, // Unix timestamp
    pub pubkey_hash: String, // SHA-256 hash of SPKI for DANE
}

impl StoredCertificate {
    /// Check if certificate expires within the given duration (seconds)
    pub fn expires_within(&self, seconds: i64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.not_after - now < seconds
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        self.expires_within(0)
    }

    /// Parse certificate PEM and extract expiry and public key hash
    pub fn from_pem(
        domain: String,
        cert_pem: String,
        key_pem: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (not_after, pubkey_hash) = Self::parse_cert_info(&cert_pem)?;
        Ok(Self {
            domain,
            cert_pem,
            key_pem,
            not_after,
            pubkey_hash,
        })
    }

    fn parse_cert_info(cert_pem: &str) -> Result<(i64, String), Box<dyn std::error::Error + Send + Sync>> {
        // Parse PEM to DER
        let p = pem_parse(cert_pem)?;
        let (_, cert) = X509Certificate::from_der(p.contents())?;

        // Get expiry
        let not_after = cert.validity().not_after.timestamp();

        // Get SPKI hash for DANE
        let spki = cert.public_key().raw;
        let mut hasher = Sha256::new();
        hasher.update(spki);
        let hash = hasher.finalize();
        let pubkey_hash = hex::encode(hash);

        Ok((not_after, pubkey_hash))
    }

    /// Get certificate chain as rustls CertificateDer
    pub fn cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut certs = Vec::new();
        for p in pem_parse_many(&self.cert_pem)? {
            let contents: Vec<u8> = p.into_contents();
            certs.push(CertificateDer::from(contents));
        }
        Ok(certs)
    }

    /// Get private key as rustls PrivateKeyDer
    pub fn private_key(&self) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
        let p = pem_parse(&self.key_pem)?;
        let tag = p.tag().to_string();
        let contents = p.into_contents();
        match tag.as_str() {
            "PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs8(contents.into())),
            "EC PRIVATE KEY" => Ok(PrivateKeyDer::Sec1(contents.into())),
            "RSA PRIVATE KEY" => Ok(PrivateKeyDer::Pkcs1(contents.into())),
            _ => Err("Unknown private key format".into()),
        }
    }
}

/// Manages certificates for the mail server
pub struct CertificateManager {
    storage_path: std::path::PathBuf,
    hostname_cert: Option<StoredCertificate>,
    mta_sts_cert: Option<StoredCertificate>,
}

impl CertificateManager {
    pub fn new(storage_path: &Path) -> Self {
        Self {
            storage_path: storage_path.to_path_buf(),
            hostname_cert: None,
            mta_sts_cert: None,
        }
    }

    /// Load certificates from storage
    pub async fn load(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certs_dir = self.storage_path.join("certs");
        
        // Load hostname certificate
        let hostname_path = certs_dir.join("hostname.json");
        if hostname_path.exists() {
            let data = fs::read_to_string(&hostname_path).await?;
            self.hostname_cert = Some(serde_json::from_str(&data)?);
            println!("Loaded hostname certificate");
        }

        // Load MTA-STS certificate
        let mta_sts_path = certs_dir.join("mta_sts.json");
        if mta_sts_path.exists() {
            let data = fs::read_to_string(&mta_sts_path).await?;
            self.mta_sts_cert = Some(serde_json::from_str(&data)?);
            println!("Loaded MTA-STS certificate");
        }

        Ok(())
    }

    /// Save certificates to storage
    async fn save_cert(
        &self,
        cert: &StoredCertificate,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certs_dir = self.storage_path.join("certs");
        fs::create_dir_all(&certs_dir).await?;

        let path = certs_dir.join(format!("{}.json", name));
        let data = serde_json::to_string_pretty(cert)?;
        fs::write(&path, data).await?;

        Ok(())
    }

    /// Get the hostname certificate
    pub fn hostname_cert(&self) -> Option<&StoredCertificate> {
        self.hostname_cert.as_ref()
    }

    /// Get the MTA-STS certificate
    pub fn mta_sts_cert(&self) -> Option<&StoredCertificate> {
        self.mta_sts_cert.as_ref()
    }

    /// Request or renew the hostname certificate
    pub async fn ensure_hostname_cert(
        &mut self,
        hostname: &str,
        dns_client: &CloudflareClient,
        dane_manager: &mut DaneManager,
    ) -> Result<&StoredCertificate, Box<dyn std::error::Error + Send + Sync>> {
        // Check if we need a new certificate (missing or expires within 30 days)
        let need_new = match &self.hostname_cert {
            Some(cert) => cert.expires_within(30 * 24 * 60 * 60),
            None => true,
        };

        if need_new {
            println!("Requesting new certificate for {}", hostname);
            
            let old_cert = self.hostname_cert.clone();
            
            // Request new certificate
            let mut acme = AcmeClient::new().await?;
            let (cert_pem, key_pem) = acme.request_certificate(hostname, dns_client).await?;
            
            let new_cert = StoredCertificate::from_pem(
                hostname.to_string(),
                cert_pem,
                key_pem,
            )?;

            // Handle DANE rollover if we have an old cert
            if let Some(old) = old_cert {
                dane_manager.start_rollover(hostname, &old.pubkey_hash, &new_cert.pubkey_hash, dns_client).await?;
            } else {
                // First time, just set the DANE record
                dane_manager.set_initial_record(hostname, &new_cert.pubkey_hash, dns_client).await?;
            }

            self.hostname_cert = Some(new_cert);
            self.save_cert(self.hostname_cert.as_ref().unwrap(), "hostname").await?;
            
            println!("Certificate for {} saved", hostname);
        }

        Ok(self.hostname_cert.as_ref().unwrap())
    }

    /// Request or renew the MTA-STS certificate
    pub async fn ensure_mta_sts_cert(
        &mut self,
        mail_domain: &str,
        dns_client: &CloudflareClient,
    ) -> Result<&StoredCertificate, Box<dyn std::error::Error + Send + Sync>> {
        let mta_sts_domain = format!("mta-sts.{}", mail_domain);
        
        // Check if we need a new certificate
        let need_new = match &self.mta_sts_cert {
            Some(cert) => cert.expires_within(30 * 24 * 60 * 60),
            None => true,
        };

        if need_new {
            println!("Requesting new certificate for {}", mta_sts_domain);
            
            let mut acme = AcmeClient::new().await?;
            let (cert_pem, key_pem) = acme.request_certificate(&mta_sts_domain, dns_client).await?;
            
            let new_cert = StoredCertificate::from_pem(
                mta_sts_domain.clone(),
                cert_pem,
                key_pem,
            )?;

            self.mta_sts_cert = Some(new_cert);
            self.save_cert(self.mta_sts_cert.as_ref().unwrap(), "mta_sts").await?;
            
            println!("Certificate for {} saved", mta_sts_domain);
        }

        Ok(self.mta_sts_cert.as_ref().unwrap())
    }
}
