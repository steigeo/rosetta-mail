/// DNS record types we need to manage
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    MX,
    TXT,
    TLSA,
    CAA,
    CNAME,
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::TLSA => "TLSA",
            DnsRecordType::CAA => "CAA",
            DnsRecordType::CNAME => "CNAME",
        }
    }
}

/// A DNS record to be created or updated
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub proxied: bool,
}

impl DnsRecord {
    pub fn a(name: &str, ip: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::A,
            content: ip.to_string(),
            ttl,
            priority: None,
            proxied: false,
        }
    }

    pub fn aaaa(name: &str, ip: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::AAAA,
            content: ip.to_string(),
            ttl,
            priority: None,
            proxied: false,
        }
    }

    pub fn mx(name: &str, target: &str, priority: u16, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::MX,
            content: target.to_string(),
            ttl,
            priority: Some(priority),
            proxied: false,
        }
    }

    pub fn txt(name: &str, content: &str, ttl: u32) -> Self {
        // Cloudflare expects TXT record content wrapped in quotes
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::TXT,
            content: format!("\"{}\"", content),
            ttl,
            priority: None,
            proxied: false,
        }
    }

    pub fn tlsa(name: &str, usage: u8, selector: u8, matching_type: u8, hash: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::TLSA,
            content: format!("{} {} {} {}", usage, selector, matching_type, hash),
            ttl,
            priority: None,
            proxied: false,
        }
    }

    pub fn caa(name: &str, flags: u8, tag: &str, value: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::CAA,
            content: format!("{} {} \"{}\"", flags, tag, value),
            ttl,
            priority: None,
            proxied: false,
        }
    }

    pub fn cname(name: &str, target: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            record_type: DnsRecordType::CNAME,
            content: target.to_string(),
            ttl,
            priority: None,
            proxied: false,
        }
    }
}

/// DMARC policy
pub fn dmarc_record(mail_domain: &str) -> DnsRecord {
    DnsRecord::txt(
        &format!("_dmarc.{}", mail_domain),
        "v=DMARC1; p=reject; adkim=s; aspf=s;",
        3600,
    )
}

/// SPF record - includes the hostname's A record
/// For IPv6 support, use spf_record_with_ips
pub fn spf_record(mail_domain: &str, hostname: &str) -> DnsRecord {
    DnsRecord::txt(
        mail_domain,
        &format!("v=spf1 a:{} -all", hostname),
        3600,
    )
}

/// SPF record with explicit IPv4 and/or IPv6 addresses
pub fn spf_record_with_ips(mail_domain: &str, hostname: &str, ipv4: Option<&str>, ipv6: Option<&str>) -> DnsRecord {
    let mut mechanisms = vec![format!("a:{}", hostname)];
    
    // Add explicit IPv4 if provided
    if let Some(ip4) = ipv4 {
        mechanisms.push(format!("ip4:{}", ip4));
    }
    
    // Add explicit IPv6 if provided
    if let Some(ip6) = ipv6 {
        mechanisms.push(format!("ip6:{}", ip6));
    }
    
    DnsRecord::txt(
        mail_domain,
        &format!("v=spf1 {} -all", mechanisms.join(" ")),
        3600,
    )
}

/// DKIM record
pub fn dkim_record(mail_domain: &str, public_key_base64: &str) -> DnsRecord {
    DnsRecord::txt(
        &format!("dkim._domainkey.{}", mail_domain),
        &format!("v=DKIM1; k=rsa; p={}", public_key_base64),
        3600,
    )
}

/// MTA-STS record
pub fn mta_sts_record(mail_domain: &str) -> DnsRecord {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    DnsRecord::txt(
        &format!("_mta-sts.{}", mail_domain),
        &format!("v=STSv1; id={};", timestamp),
        3600,
    )
}

/// MX record
pub fn mx_record(mail_domain: &str, hostname: &str) -> DnsRecord {
    DnsRecord::mx(mail_domain, hostname, 10, 3600)
}

/// DANE TLSA record for SMTP (port 25)
pub fn dane_tlsa_record(hostname: &str, cert_pubkey_hash: &str) -> DnsRecord {
    // TLSA 3 1 1 = DANE-EE, SubjectPublicKeyInfo, SHA-256
    DnsRecord::tlsa(
        &format!("_25._tcp.{}", hostname),
        3, 1, 1,
        cert_pubkey_hash,
        3600,
    )
}

/// CAA record to restrict certificate issuance
pub fn caa_record_issue(hostname: &str) -> DnsRecord {
    DnsRecord::caa(
        hostname,
        0,
        "issue",
        "letsencrypt.org;validationmethods=dns-01",
        3600,
    )
}

/// CAA record to block wildcard issuance
pub fn caa_record_issuewild(hostname: &str) -> DnsRecord {
    DnsRecord::caa(hostname, 0, "issuewild", ";", 3600)
}

/// ACME DNS-01 challenge record
pub fn acme_challenge_record(domain: &str, challenge_response: &str) -> DnsRecord {
    DnsRecord::txt(
        &format!("_acme-challenge.{}", domain),
        challenge_response,
        60, // Short TTL for challenges
    )
}

/// A record for hostname
pub fn a_record(hostname: &str, ip: &str) -> DnsRecord {
    DnsRecord::a(hostname, ip, 3600)
}

/// AAAA record for hostname (IPv6)
pub fn aaaa_record(hostname: &str, ip: &str) -> DnsRecord {
    DnsRecord::aaaa(hostname, ip, 3600)
}

/// CNAME record pointing one hostname to another
pub fn cname_record(name: &str, target: &str) -> DnsRecord {
    DnsRecord::cname(name, target, 3600)
}
