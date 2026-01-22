/// Outbound mail delivery service
/// 
/// This module handles sending emails to external servers by:
/// 1. Looking up MX records for the recipient domain
/// 2. Establishing a connection via the tunnel server
/// 3. Negotiating STARTTLS with DANE/MTA-STS verification
/// 4. Sending the email with DKIM signature

use crate::client::smtp::outbound::async_client::AsyncSmtpClient;
use crate::client::smtp::MailTransaction;
use crate::proto::TunnelMessage;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// Error type for mail delivery
#[derive(Debug)]
pub enum MailerError {
    /// DNS lookup failed
    DnsError(String),
    /// Connection failed
    ConnectionError(String),
    /// SMTP protocol error
    SmtpError(String),
    /// TLS error
    TlsError(String),
    /// DKIM signing error
    DkimError(String),
    /// All MX hosts failed
    AllMxFailed(Vec<String>),
}

impl std::fmt::Display for MailerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DnsError(s) => write!(f, "DNS error: {}", s),
            Self::ConnectionError(s) => write!(f, "Connection error: {}", s),
            Self::SmtpError(s) => write!(f, "SMTP error: {}", s),
            Self::TlsError(s) => write!(f, "TLS error: {}", s),
            Self::DkimError(s) => write!(f, "DKIM error: {}", s),
            Self::AllMxFailed(errors) => write!(f, "All MX hosts failed: {}", errors.join("; ")),
        }
    }
}

impl std::error::Error for MailerError {}

/// Configuration for the mailer
pub struct MailerConfig {
    /// Our hostname (for EHLO)
    pub hostname: String,
    /// Domain for DKIM signing
    pub mail_domain: String,
    /// DKIM selector
    pub dkim_selector: String,
}

/// Mail delivery service
pub struct Mailer {
    config: MailerConfig,
    #[allow(dead_code)]
    tx: mpsc::Sender<TunnelMessage>,
}

impl Mailer {
    pub fn new(
        config: MailerConfig,
        tx: mpsc::Sender<TunnelMessage>,
    ) -> Self {
        Self {
            config,
            tx,
        }
    }

    /// Send an email to its recipients
    /// 
    /// Groups recipients by domain and sends to each domain's MX servers
    pub async fn send(&self, transaction: &MailTransaction) -> Result<(), MailerError> {
        // Group recipients by domain
        let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
        
        for rcpt in &transaction.rcpt_to {
            let domain = rcpt.split('@').last().unwrap_or("").to_lowercase();
            if domain.is_empty() {
                continue;
            }
            by_domain.entry(domain).or_default().push(rcpt.clone());
        }

        // TODO: Sign the email with DKIM
        let email_data = transaction.data.clone();

        // Send to each domain
        let mut errors = Vec::new();
        let domain_count = by_domain.len();
        for (domain, recipients) in by_domain {
            if let Err(e) = self.send_to_domain(&domain, &transaction.mail_from, &recipients, &email_data).await {
                errors.push(format!("{}: {}", domain, e));
            }
        }

        if !errors.is_empty() && errors.len() == domain_count {
            return Err(MailerError::AllMxFailed(errors));
        }

        Ok(())
    }

    /// Send email to a specific domain
    async fn send_to_domain(
        &self,
        domain: &str,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
    ) -> Result<(), MailerError> {
        // Look up MX records
        let mx_hosts = self.lookup_mx(domain).await?;
        
        if mx_hosts.is_empty() {
            // No MX records, try the domain directly
            return self.try_send_to_host(domain, 25, mail_from, recipients, email_data).await;
        }

        // Try each MX host in order of priority
        let mut errors = Vec::new();
        for mx_host in mx_hosts {
            match self.try_send_to_host(&mx_host, 25, mail_from, recipients, email_data).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    errors.push(format!("{}: {}", mx_host, e));
                    continue;
                }
            }
        }

        Err(MailerError::AllMxFailed(errors))
    }

    /// Look up MX records for a domain
    async fn lookup_mx(&self, _domain: &str) -> Result<Vec<String>, MailerError> {
        // TODO: Use actual DNS lookup via the DNS module
        // For now, return empty to trigger direct delivery
        Ok(vec![])
    }

    /// Try to send to a specific host
    async fn try_send_to_host(
        &self,
        _host: &str,
        _port: u16,
        _mail_from: &str,
        _recipients: &[String],
        _email_data: &[u8],
    ) -> Result<(), MailerError> {
        // Request outbound connection via tunnel server
        // TODO: Implement actual connection via server WebSocket
        
        // For now, return an error indicating not implemented
        Err(MailerError::ConnectionError("Outbound connections not yet implemented".to_string()))
    }

    /// Send email over an established SMTP connection
    pub async fn send_over_connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
    ) -> Result<(), MailerError> {
        let mut client = AsyncSmtpClient::new(stream, &self.config.hostname);

        // Read greeting
        let greeting = client.read_greeting().await
            .map_err(|e| MailerError::SmtpError(e.to_string()))?;
        
        if !greeting.is_2xx() {
            return Err(MailerError::SmtpError(format!(
                "Bad greeting: {} {}", greeting.code, greeting.lines.join(" ")
            )));
        }

        // Send EHLO
        let ehlo_reply = client.ehlo().await
            .map_err(|e| MailerError::SmtpError(e.to_string()))?;
        
        if !ehlo_reply.is_2xx() {
            return Err(MailerError::SmtpError(format!(
                "EHLO rejected: {} {}", ehlo_reply.code, ehlo_reply.lines.join(" ")
            )));
        }

        // TODO: Check for STARTTLS and upgrade connection
        // TODO: Verify DANE/MTA-STS

        // Send MAIL FROM
        let mail_reply = client.mail_from(mail_from).await
            .map_err(|e| MailerError::SmtpError(e.to_string()))?;
        
        if !mail_reply.is_2xx() {
            return Err(MailerError::SmtpError(format!(
                "MAIL FROM rejected: {} {}", mail_reply.code, mail_reply.lines.join(" ")
            )));
        }

        // Send RCPT TO for each recipient
        for rcpt in recipients {
            let rcpt_reply = client.rcpt_to(rcpt).await
                .map_err(|e| MailerError::SmtpError(e.to_string()))?;
            
            if !rcpt_reply.is_2xx() {
                // Log but continue with other recipients
                eprintln!("Warning: RCPT TO <{}> rejected: {} {}", 
                    rcpt, rcpt_reply.code, rcpt_reply.lines.join(" "));
            }
        }

        // Send DATA
        let data_reply = client.data(email_data).await
            .map_err(|e| MailerError::SmtpError(e.to_string()))?;
        
        if !data_reply.is_2xx() {
            return Err(MailerError::SmtpError(format!(
                "DATA rejected: {} {}", data_reply.code, data_reply.lines.join(" ")
            )));
        }

        // Send QUIT
        let _ = client.quit().await;

        Ok(())
    }
}
