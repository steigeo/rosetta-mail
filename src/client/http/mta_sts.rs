/// MTA-STS policy generation
/// See RFC 8461 for details

/// MTA-STS policy
pub struct MtaStsPolicy {
    pub hostname: String,
    pub mail_domain: String,
    pub max_age: u64,
}

impl MtaStsPolicy {
    pub fn new(hostname: String, mail_domain: String) -> Self {
        Self {
            hostname,
            mail_domain,
            max_age: 86400 * 7, // 7 days default
        }
    }

    /// Generate the policy text for /.well-known/mta-sts.txt
    pub fn policy_text(&self) -> String {
        format!(
            "version: STSv1\r\n\
             mode: enforce\r\n\
             mx: {}\r\n\
             max_age: {}\r\n",
            self.hostname, self.max_age
        )
    }

    /// Generate the _mta-sts DNS TXT record value
    pub fn dns_record_value(&self) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("v=STSv1; id={}", timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_text() {
        let policy = MtaStsPolicy::new("mail.example.com".into(), "example.com".into());
        let text = policy.policy_text();
        assert!(text.contains("version: STSv1"));
        assert!(text.contains("mode: enforce"));
        assert!(text.contains("mx: mail.example.com"));
        assert!(text.contains("max_age:"));
    }
}
