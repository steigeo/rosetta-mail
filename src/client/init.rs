use crate::client::config::{
    get_cloudflare_api_token, get_cloudflare_zone_id, get_mail_domain, get_server_ip,
    get_server_ipv6, get_smtp_hostname, get_storage_path,
};
use crate::{log_error, log_info, verbose};
use crate::client::dns::{
    a_record, aaaa_record, caa_record_issue, cname_record, dkim_record, dmarc_record, mx_record,
    spf_record_with_ips, CloudflareClient, DnsRecord,
};
use crate::client::tls::certificate::{CertificateManager, StoredCertificate};
use crate::client::tls::dane::DaneManager;
use crate::client::tls::dkim::DkimKeyPair;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for TLS and DNS configuration
pub struct EmailConfig {
    pub hostname: String,
    pub mail_domain: String,
    pub certificate: Option<StoredCertificate>,
    pub mta_sts_certificate: Option<StoredCertificate>,
    pub dkim_keypair: Option<Arc<DkimKeyPair>>,
    pub tls_available: bool,
}

impl EmailConfig {
    pub fn new(hostname: String, mail_domain: String) -> Self {
        Self {
            hostname,
            mail_domain,
            certificate: None,
            mta_sts_certificate: None,
            dkim_keypair: None,
            tls_available: false,
        }
    }
}

/// Result of initialization
pub struct InitResult {
    pub config: Arc<RwLock<EmailConfig>>,
    pub storage_path: PathBuf,
}

/// Initialize email infrastructure: DKIM, certificates, DNS records
pub async fn initialize() -> Result<Option<InitResult>, Box<dyn std::error::Error + Send + Sync>> {
    let storage_path = get_storage_path();
    
    // Check required configuration
    let hostname = match get_smtp_hostname() {
        Some(h) => h,
        None => {
            println!("Warning: SMTP_HOSTNAME not set, TLS/DNS features disabled");
            return Ok(None);
        }
    };

    let mail_domain = match get_mail_domain() {
        Some(d) => d,
        None => {
            println!("Warning: MAIL_DOMAIN not set, using hostname as mail domain");
            hostname.clone()
        }
    };

    log_info!("Initializing email infrastructure...");
    verbose!("  Hostname: {}", hostname);
    verbose!("  Mail domain: {}", mail_domain);
    verbose!("  Storage path: {:?}", storage_path);

    let mut config = EmailConfig::new(hostname.clone(), mail_domain.clone());

    // Load or generate DKIM keys
    verbose!("\n--- DKIM Setup ---");
    match DkimKeyPair::load_or_generate(&storage_path).await {
        Ok(keypair) => {
            verbose!("DKIM keypair ready");
            config.dkim_keypair = Some(Arc::new(keypair));
        }
        Err(e) => {
            log_error!("Warning: Failed to load/generate DKIM keys: {}", e);
        }
    }

    // Check if we have Cloudflare credentials for DNS management
    let dns_client = match (get_cloudflare_api_token(), get_cloudflare_zone_id()) {
        (Some(token), Some(zone_id)) => {
            verbose!("\n--- Cloudflare DNS Setup ---");
            Some(CloudflareClient::new(token, zone_id))
        }
        _ => {
            println!("\nWarning: Cloudflare credentials not set, skipping DNS record management");
            println!("  Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID for automatic DNS setup");
            None
        }
    };

    // Set up DNS records if we have Cloudflare access
    if let Some(ref dns) = dns_client {
        setup_dns_records(dns, &hostname, &mail_domain, &config).await?;
    }

    // Set up certificates if we have Cloudflare access
    if let Some(ref dns) = dns_client {
        verbose!("\n--- Certificate Setup ---");
        
        let mut cert_manager = CertificateManager::new(&storage_path);
        cert_manager.load().await?;

        let mut dane_manager = DaneManager::new(&storage_path);
        dane_manager.load().await?;

        // Check and complete any pending DANE rollover
        dane_manager.check_and_complete_rollover(dns).await?;

        // Ensure we have a valid certificate for the hostname (SMTP)
        match cert_manager.ensure_hostname_cert(&hostname, dns, &mut dane_manager).await {
            Ok(cert) => {
                verbose!("Certificate for {} is valid", hostname);
                config.certificate = Some(cert.clone());
                config.tls_available = true;
            }
            Err(e) => {
                log_error!("Warning: Failed to obtain certificate for {}: {}", hostname, e);
                log_error!("STARTTLS will be disabled");
            }
        }

        // Also get a certificate for mta-sts.<mail_domain> (HTTPS)
        match cert_manager.ensure_mta_sts_cert(&mail_domain, dns).await {
            Ok(cert) => {
                verbose!("Certificate for {} is valid", cert.domain);
                config.mta_sts_certificate = Some(cert.clone());
            }
            Err(e) => {
                log_error!("Warning: Failed to obtain certificate for mta-sts.{}: {}", mail_domain, e);
                log_error!("MTA-STS HTTPS will not work");
            }
        }
    } else {
        verbose!("\nNote: Certificates require Cloudflare DNS for ACME DNS-01 challenges");
    }

    verbose!("\n--- Initialization Complete ---");
    log_info!("TLS available: {}", config.tls_available);

    Ok(Some(InitResult {
        config: Arc::new(RwLock::new(config)),
        storage_path,
    }))
}

/// Helper to upsert a DNS record with caching feedback
async fn upsert_dns_record(
    dns: &CloudflareClient,
    record: &DnsRecord,
    description: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match dns.upsert_record_if_changed(record).await {
        Ok((_, changed)) => {
            if changed {
                verbose!("  {} [updated]", description);
            } else {
                verbose!("  {} [unchanged]", description);
            }
        }
        Err(e) => {
            log_error!("  Warning: Failed to set {}: {}", description, e);
        }
    }
    Ok(())
}

/// Set up required DNS records for email
async fn setup_dns_records(
    dns: &CloudflareClient,
    hostname: &str,
    mail_domain: &str,
    config: &EmailConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    verbose!("Checking DNS records (only updating if changed)...");

    let server_ipv4 = get_server_ip();
    let server_ipv6 = get_server_ipv6();

    // A record for hostname pointing to the server IPv4
    if let Some(ref ip) = server_ipv4 {
        let a = a_record(hostname, ip);
        upsert_dns_record(dns, &a, &format!("A {} -> {}", hostname, ip)).await?;
    }

    // AAAA record for hostname pointing to the server IPv6
    if let Some(ref ip6) = server_ipv6 {
        let aaaa = aaaa_record(hostname, ip6);
        upsert_dns_record(dns, &aaaa, &format!("AAAA {} -> {}", hostname, ip6)).await?;
    }

    if server_ipv4.is_some() || server_ipv6.is_some() {
        // CNAME for mta-sts subdomain pointing to hostname (for MTA-STS HTTPS endpoint)
        let mta_sts_host = format!("mta-sts.{}", mail_domain);
        let cname = cname_record(&mta_sts_host, hostname);
        upsert_dns_record(dns, &cname, &format!("CNAME {} -> {}", mta_sts_host, hostname)).await?;

        // CAA records for hostname and mta-sts subdomain (allow Let's Encrypt)
        // Only set on specific subdomains, not the entire mail domain
        let caa_hostname = caa_record_issue(hostname);
        upsert_dns_record(dns, &caa_hostname, &format!("CAA {} (letsencrypt.org)", hostname)).await?;

        let caa_mta_sts = caa_record_issue(&mta_sts_host);
        upsert_dns_record(dns, &caa_mta_sts, &format!("CAA {} (letsencrypt.org)", mta_sts_host)).await?;
    } else {
        verbose!("  Note: No server IP configured, skipping A/AAAA, CNAME, and CAA records");
    }

    // MX record pointing to our hostname
    let mx = mx_record(mail_domain, hostname);
    upsert_dns_record(dns, &mx, &format!("MX {} -> {}", mail_domain, hostname)).await?;

    // SPF record with both IPv4 and IPv6
    let spf = spf_record_with_ips(
        mail_domain,
        hostname,
        server_ipv4.as_deref(),
        server_ipv6.as_deref(),
    );
    upsert_dns_record(dns, &spf, "SPF record").await?;

    // DMARC record
    let dmarc = dmarc_record(mail_domain);
    upsert_dns_record(dns, &dmarc, "DMARC record").await?;

    // DKIM record if we have a keypair
    if let Some(ref keypair) = config.dkim_keypair {
        match keypair.public_key_base64() {
            Ok(pubkey) => {
                let dkim = dkim_record(mail_domain, &pubkey);
                upsert_dns_record(dns, &dkim, "DKIM record (selector: dkim)").await?;
            }
            Err(e) => {
                log_error!("  Warning: Failed to get DKIM public key: {}", e);
            }
        }
    }

    Ok(())
}
