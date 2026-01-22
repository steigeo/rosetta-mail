use super::command::{parse_command, SmtpCommand};
use super::response::SmtpResponse;
use super::transaction::MailTransaction;

/// SMTP session states
#[derive(Debug, Clone, PartialEq)]
pub enum SmtpState {
    /// Initial state, waiting for client to send HELO/EHLO
    Connected,
    /// Client has identified itself
    Greeted,
    /// STARTTLS initiated, waiting for TLS handshake
    StartTls,
    /// MAIL FROM has been accepted
    MailFrom,
    /// At least one RCPT TO has been accepted
    RcptTo,
    /// Receiving DATA
    Data,
    /// Session is closing
    Closing,
}

/// Result of processing SMTP input
pub struct SmtpResult {
    /// Response data to send back
    pub response: Vec<u8>,
    /// Whether connection should close
    pub should_close: bool,
    /// Whether to start TLS handshake
    pub start_tls: bool,
    /// Completed mail transaction if any
    pub completed_transaction: Option<MailTransaction>,
}

impl SmtpResult {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            should_close: false,
            start_tls: false,
            completed_transaction: None,
        }
    }

    #[allow(dead_code)]
    fn with_close(mut self) -> Self {
        self.should_close = true;
        self
    }

    fn with_start_tls(mut self) -> Self {
        self.start_tls = true;
        self
    }

    #[allow(dead_code)]
    fn with_transaction(mut self, transaction: MailTransaction) -> Self {
        self.completed_transaction = Some(transaction);
        self
    }
}

/// SMTP session for a single connection
#[derive(Clone)]
pub struct SmtpSession {
    /// Current state of the session
    pub state: SmtpState,
    /// Client's identification (from HELO/EHLO)
    pub client_id: String,
    /// Whether client used EHLO (extended SMTP)
    pub is_esmtp: bool,
    /// Whether TLS is enabled for this session
    pub tls_enabled: bool,
    /// Whether TLS is available (certificate loaded)
    pub tls_available: bool,
    /// Current mail transaction
    pub transaction: MailTransaction,
    /// Server hostname
    pub hostname: String,
    /// Remote address of the client
    pub remote_addr: String,
    /// Buffer for collecting DATA content
    data_buffer: Vec<u8>,
    /// Whether this is a submission port (465/587) requiring auth
    pub submission_mode: bool,
    /// Authenticated user email (if any)
    pub authenticated_user: Option<String>,
    /// Whether the greeting has been sent
    sent_greeting: bool,
    /// Auth mechanism in progress (if any)
    auth_in_progress: Option<AuthInProgress>,
    /// Accounts config for password verification  
    accounts: Option<crate::client::config::AccountsConfig>,
}

/// State for AUTH in progress
#[derive(Clone)]
pub struct AuthInProgress {
    /// The mechanism being used
    pub mechanism: String,
    /// Username collected so far (for LOGIN)
    pub username: Option<String>,
}

impl SmtpSession {
    pub fn new(hostname: impl Into<String>, remote_addr: impl Into<String>) -> Self {
        Self {
            state: SmtpState::Connected,
            client_id: String::new(),
            is_esmtp: false,
            tls_enabled: false,
            tls_available: false,
            transaction: MailTransaction::new(),
            hostname: hostname.into(),
            remote_addr: remote_addr.into(),
            data_buffer: Vec::new(),
            submission_mode: false,
            authenticated_user: None,
            sent_greeting: false,
            auth_in_progress: None,
            accounts: None,
        }
    }

    /// Set accounts configuration for authentication
    pub fn set_accounts(&mut self, accounts: crate::client::config::AccountsConfig) {
        self.accounts = Some(accounts);
    }

    /// Set TLS availability
    pub fn set_tls_available(&mut self, available: bool) {
        self.tls_available = available;
    }

    /// Set submission mode (requires authentication)
    pub fn set_submission_mode(&mut self, submission: bool) {
        self.submission_mode = submission;
    }

    /// Set TLS enabled state (after STARTTLS)
    pub fn set_tls_enabled(&mut self, enabled: bool) {
        self.tls_enabled = enabled;
    }

    /// Check if greeting has been sent
    pub fn has_sent_greeting(&self) -> bool {
        self.sent_greeting
    }

    /// Get the initial greeting to send when connection is established
    pub fn greeting(&mut self) -> Vec<u8> {
        self.sent_greeting = true;
        SmtpResponse::service_ready(&self.hostname).to_bytes()
    }

    /// Process input and return response(s)
    /// Returns (response_bytes, should_close, start_tls, completed_transaction)
    pub fn process_input(&mut self, input: &[u8]) -> (Vec<u8>, bool, bool, Option<MailTransaction>) {
        if self.state == SmtpState::Data {
            let (response, should_close, completed_transaction) = self.process_data_input(input);
            return (response, should_close, false, completed_transaction);
        }

        // Convert to string for command parsing
        let input_str = String::from_utf8_lossy(input);
        
        // Handle multiple commands in one input (separated by CRLF)
        let mut all_responses = Vec::new();
        let mut should_close = false;
        let mut start_tls = false;
        let mut completed_transaction = None;

        for line in input_str.lines() {
            if line.is_empty() {
                continue;
            }

            // Check if we're waiting for AUTH continuation
            let (response, close, tls, transaction) = if self.is_auth_in_progress() {
                let (resp, close, trans) = self.handle_auth_continuation(line);
                (resp, close, false, trans)
            } else {
                self.process_command(line)
            };
            
            all_responses.extend(response);
            
            if close {
                should_close = true;
            }
            if tls {
                start_tls = true;
            }
            if transaction.is_some() {
                completed_transaction = transaction;
            }
        }

        (all_responses, should_close, start_tls, completed_transaction)
    }

    /// Process a single SMTP command (legacy interface)
    fn process_command(&mut self, line: &str) -> (Vec<u8>, bool, bool, Option<MailTransaction>) {
        let command = parse_command(line);
        
        match command {
            SmtpCommand::Helo(domain) => {
                let (resp, close, trans) = self.handle_helo(domain, false);
                (resp, close, false, trans)
            }
            SmtpCommand::Ehlo(domain) => {
                let (resp, close, trans) = self.handle_helo(domain, true);
                (resp, close, false, trans)
            }
            SmtpCommand::MailFrom { address, .. } => {
                let (resp, close, trans) = self.handle_mail_from(address);
                (resp, close, false, trans)
            }
            SmtpCommand::RcptTo { address, .. } => {
                let (resp, close, trans) = self.handle_rcpt_to(address);
                (resp, close, false, trans)
            }
            SmtpCommand::Data => {
                let (resp, close, trans) = self.handle_data();
                (resp, close, false, trans)
            }
            SmtpCommand::Rset => {
                let (resp, close, trans) = self.handle_rset();
                (resp, close, false, trans)
            }
            SmtpCommand::Vrfy(_) => {
                let (resp, close, trans) = self.handle_vrfy();
                (resp, close, false, trans)
            }
            SmtpCommand::Expn(_) => {
                let (resp, close, trans) = self.handle_expn();
                (resp, close, false, trans)
            }
            SmtpCommand::Help(_) => {
                let (resp, close, trans) = self.handle_help();
                (resp, close, false, trans)
            }
            SmtpCommand::Noop(_) => {
                let (resp, close, trans) = self.handle_noop();
                (resp, close, false, trans)
            }
            SmtpCommand::Quit => {
                let (resp, close, trans) = self.handle_quit();
                (resp, close, false, trans)
            }
            SmtpCommand::StartTls => {
                let result = self.handle_starttls();
                (result.response, result.should_close, result.start_tls, result.completed_transaction)
            }
            SmtpCommand::Auth { mechanism, initial_response } => {
                let (resp, close, trans) = self.handle_auth(&mechanism, initial_response.as_deref());
                (resp, close, false, trans)
            }
            SmtpCommand::Unknown(_) => (SmtpResponse::syntax_error().to_bytes(), false, false, None),
        }
    }

    fn handle_helo(&mut self, domain: String, is_esmtp: bool) -> (Vec<u8>, bool, Option<MailTransaction>) {
        self.client_id = domain;
        self.is_esmtp = is_esmtp;
        self.state = SmtpState::Greeted;
        self.transaction.reset();

        let response = if is_esmtp {
            // Use the new EHLO response builder that includes STARTTLS
            self.build_ehlo_response()
        } else {
            SmtpResponse::ok(format!("{} Hello {}", self.hostname, self.client_id)).to_bytes()
        };

        (response, false, None)
    }

    fn handle_mail_from(&mut self, address: String) -> (Vec<u8>, bool, Option<MailTransaction>) {
        if self.state == SmtpState::Connected {
            return (SmtpResponse::bad_sequence().to_bytes(), false, None);
        }

        // Require authentication for submission mode
        if self.submission_mode && self.authenticated_user.is_none() {
            return (SmtpResponse::auth_required().to_bytes(), false, None);
        }

        // Reset any previous transaction
        self.transaction.reset();
        self.transaction.set_mail_from(address.clone());
        self.state = SmtpState::MailFrom;

        (SmtpResponse::ok(format!("OK <{}>", address)).to_bytes(), false, None)
    }

    fn handle_rcpt_to(&mut self, address: String) -> (Vec<u8>, bool, Option<MailTransaction>) {
        if self.state != SmtpState::MailFrom && self.state != SmtpState::RcptTo {
            return (SmtpResponse::bad_sequence().to_bytes(), false, None);
        }

        self.transaction.add_rcpt_to(address.clone());
        self.state = SmtpState::RcptTo;

        (SmtpResponse::ok(format!("OK <{}>", address)).to_bytes(), false, None)
    }

    fn handle_data(&mut self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        if self.state != SmtpState::RcptTo {
            return (SmtpResponse::bad_sequence().to_bytes(), false, None);
        }

        self.state = SmtpState::Data;
        self.data_buffer.clear();

        (SmtpResponse::start_mail_input().to_bytes(), false, None)
    }

    fn process_data_input(&mut self, input: &[u8]) -> (Vec<u8>, bool, Option<MailTransaction>) {
        self.data_buffer.extend_from_slice(input);

        // Check if we've received the end-of-data marker (<CRLF>.<CRLF>)
        if let Some(end_pos) = find_data_end(&self.data_buffer) {
            // Extract the data (excluding the final .<CRLF>)
            let data = self.data_buffer[..end_pos].to_vec();
            
            // Unstuff dots (lines starting with .. become .)
            let unstuffed = unstuff_dots(&data);
            self.transaction.data = unstuffed;
            
            // Set outbound flags based on submission mode
            self.transaction.is_outbound = self.submission_mode;
            self.transaction.authenticated_user = self.authenticated_user.clone();

            // Complete the transaction
            let completed = self.transaction.clone();
            self.transaction.reset();
            self.data_buffer.clear();
            self.state = SmtpState::Greeted;

            println!(
                "Email received: FROM={} TO={:?} SIZE={} outbound={}",
                completed.mail_from,
                completed.rcpt_to,
                completed.data.len(),
                completed.is_outbound
            );

            (SmtpResponse::ok("OK Message accepted").to_bytes(), false, Some(completed))
        } else {
            // Still collecting data, no response yet
            (Vec::new(), false, None)
        }
    }

    fn handle_rset(&mut self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        self.transaction.reset();
        if self.state != SmtpState::Connected {
            self.state = SmtpState::Greeted;
        }
        (SmtpResponse::ok("OK").to_bytes(), false, None)
    }

    fn handle_vrfy(&self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        // VRFY is often disabled for security reasons
        (SmtpResponse::new(252, "Cannot VRFY user, but will accept message and attempt delivery").to_bytes(), false, None)
    }

    fn handle_expn(&self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        // EXPN is typically disabled for security reasons
        (SmtpResponse::not_implemented().to_bytes(), false, None)
    }

    fn handle_help(&self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        let help_text = "214-Commands supported:\r\n\
                         214-HELO EHLO MAIL RCPT DATA\r\n\
                         214-RSET NOOP QUIT HELP VRFY\r\n\
                         214 End of HELP info\r\n";
        (help_text.as_bytes().to_vec(), false, None)
    }

    fn handle_noop(&self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        (SmtpResponse::ok("OK").to_bytes(), false, None)
    }

    fn handle_quit(&mut self) -> (Vec<u8>, bool, Option<MailTransaction>) {
        self.state = SmtpState::Closing;
        (SmtpResponse::service_closing(&self.hostname).to_bytes(), true, None)
    }

    fn handle_auth(&mut self, mechanism: &str, initial_response: Option<&str>) -> (Vec<u8>, bool, Option<MailTransaction>) {
        // AUTH is only valid in submission mode after EHLO
        if !self.submission_mode {
            return (SmtpResponse::not_implemented().to_bytes(), false, None);
        }

        // AUTH requires EHLO first
        if self.state == SmtpState::Connected {
            return (SmtpResponse::bad_sequence().to_bytes(), false, None);
        }

        // Already authenticated?
        if self.authenticated_user.is_some() {
            return (SmtpResponse::new(503, "Already authenticated").to_bytes(), false, None);
        }

        // Require TLS for AUTH (if TLS is available)
        if self.tls_available && !self.tls_enabled {
            return (SmtpResponse::auth_encryption_required().to_bytes(), false, None);
        }

        match mechanism {
            "PLAIN" => self.handle_auth_plain(initial_response),
            "LOGIN" => self.handle_auth_login(initial_response),
            _ => (SmtpResponse::new(504, "Unrecognized authentication type").to_bytes(), false, None),
        }
    }

    fn handle_auth_plain(&mut self, initial_response: Option<&str>) -> (Vec<u8>, bool, Option<MailTransaction>) {
        // AUTH PLAIN format: base64(\0username\0password) or base64(authzid\0authcid\0password)
        // If no initial response, request it
        if initial_response.is_none() || initial_response == Some("=") {
            self.auth_in_progress = Some(AuthInProgress {
                mechanism: "PLAIN".to_string(),
                username: None,
            });
            // Empty challenge (just base64 continue prompt)
            return (SmtpResponse::auth_continue("").to_bytes(), false, None);
        }

        let response = initial_response.unwrap();
        self.complete_auth_plain(response)
    }

    fn complete_auth_plain(&mut self, response: &str) -> (Vec<u8>, bool, Option<MailTransaction>) {
        use base64::Engine;
        
        // Decode base64
        let decoded = match base64::engine::general_purpose::STANDARD.decode(response) {
            Ok(d) => d,
            Err(_) => return (SmtpResponse::auth_failed().to_bytes(), false, None),
        };

        // Parse PLAIN format: [authzid]\0authcid\0password
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        if parts.len() < 2 {
            return (SmtpResponse::auth_failed().to_bytes(), false, None);
        }

        // authcid (username) is second element, password is third
        // If only 2 parts, first is authcid, second is password
        let (username, password) = if parts.len() == 3 {
            // authzid, authcid, password
            (
                String::from_utf8_lossy(parts[1]).to_string(),
                String::from_utf8_lossy(parts[2]).to_string(),
            )
        } else {
            // authcid, password
            (
                String::from_utf8_lossy(parts[0]).to_string(),
                String::from_utf8_lossy(parts[1]).to_string(),
            )
        };

        self.auth_in_progress = None;
        self.verify_credentials(&username, &password)
    }

    fn handle_auth_login(&mut self, initial_response: Option<&str>) -> (Vec<u8>, bool, Option<MailTransaction>) {
        use base64::Engine;
        
        // AUTH LOGIN is a challenge-response protocol
        // If initial response provided, it's the username (base64)
        if let Some(response) = initial_response {
            if response != "=" {
                // Decode username
                let username = match base64::engine::general_purpose::STANDARD.decode(response) {
                    Ok(d) => String::from_utf8_lossy(&d).to_string(),
                    Err(_) => return (SmtpResponse::auth_failed().to_bytes(), false, None),
                };
                
                self.auth_in_progress = Some(AuthInProgress {
                    mechanism: "LOGIN".to_string(),
                    username: Some(username),
                });
                
                // Request password (base64("Password:"))
                return (SmtpResponse::auth_continue("UGFzc3dvcmQ6").to_bytes(), false, None);
            }
        }
        
        // Request username (base64("Username:"))
        self.auth_in_progress = Some(AuthInProgress {
            mechanism: "LOGIN".to_string(),
            username: None,
        });
        (SmtpResponse::auth_continue("VXNlcm5hbWU6").to_bytes(), false, None)
    }

    /// Handle AUTH continuation (client response to challenge)
    pub fn handle_auth_continuation(&mut self, response: &str) -> (Vec<u8>, bool, Option<MailTransaction>) {
        use base64::Engine;
        
        let auth_state = match self.auth_in_progress.take() {
            Some(s) => s,
            None => return (SmtpResponse::bad_sequence().to_bytes(), false, None),
        };

        match auth_state.mechanism.as_str() {
            "PLAIN" => self.complete_auth_plain(response),
            "LOGIN" => {
                // Decode the response
                let decoded = match base64::engine::general_purpose::STANDARD.decode(response) {
                    Ok(d) => String::from_utf8_lossy(&d).to_string(),
                    Err(_) => return (SmtpResponse::auth_failed().to_bytes(), false, None),
                };

                if auth_state.username.is_none() {
                    // This is the username response
                    self.auth_in_progress = Some(AuthInProgress {
                        mechanism: "LOGIN".to_string(),
                        username: Some(decoded),
                    });
                    // Request password
                    (SmtpResponse::auth_continue("UGFzc3dvcmQ6").to_bytes(), false, None)
                } else {
                    // This is the password response
                    let username = auth_state.username.unwrap();
                    self.verify_credentials(&username, &decoded)
                }
            }
            _ => (SmtpResponse::auth_failed().to_bytes(), false, None),
        }
    }

    fn verify_credentials(&mut self, username: &str, password: &str) -> (Vec<u8>, bool, Option<MailTransaction>) {
        // Check credentials against accounts config
        if let Some(ref accounts) = self.accounts {
            if accounts.verify_password(username, password) {
                self.authenticated_user = Some(username.to_string());
                println!("SMTP AUTH: User {} authenticated successfully", username);
                return (SmtpResponse::auth_successful().to_bytes(), false, None);
            }
        }
        
        println!("SMTP AUTH: Failed authentication attempt for user {}", username);
        (SmtpResponse::auth_failed().to_bytes(), false, None)
    }

    /// Check if AUTH is in progress
    pub fn is_auth_in_progress(&self) -> bool {
        self.auth_in_progress.is_some()
    }

    fn handle_starttls(&mut self) -> SmtpResult {
        // STARTTLS is only valid before any mail transaction
        if self.state != SmtpState::Greeted {
            return SmtpResult::new(SmtpResponse::bad_sequence().to_bytes());
        }

        // Check if TLS is already enabled
        if self.tls_enabled {
            return SmtpResult::new(SmtpResponse::new(503, "TLS already active").to_bytes());
        }

        // Check if TLS is available
        if !self.tls_available {
            return SmtpResult::new(SmtpResponse::not_implemented().to_bytes());
        }

        // Send ready response and signal to start TLS
        self.state = SmtpState::StartTls;
        SmtpResult::new(SmtpResponse::new(220, "Ready to start TLS").to_bytes())
            .with_start_tls()
    }

    /// Called after TLS handshake completes successfully
    pub fn tls_handshake_completed(&mut self) {
        self.tls_enabled = true;
        self.state = SmtpState::Connected; // Reset state - client must re-EHLO
        self.client_id.clear();
        self.is_esmtp = false;
        self.transaction.reset();
    }

    fn build_ehlo_response(&self) -> Vec<u8> {
        let mut extensions: Vec<&str> = vec![
            "8BITMIME",
            "PIPELINING",
            "SIZE 10485760",
        ];

        // Advertise STARTTLS if available and not already enabled
        if self.tls_available && !self.tls_enabled {
            extensions.push("STARTTLS");
        }

        // Advertise AUTH for submission mode (or after STARTTLS on submission port)
        if self.submission_mode && (self.tls_enabled || !self.tls_available) {
            extensions.push("AUTH PLAIN LOGIN");
        }

        let mut response_bytes = Vec::new();
        
        // First line with hostname
        if extensions.is_empty() {
            response_bytes.extend(format!("250 {}\r\n", self.hostname).as_bytes());
        } else {
            response_bytes.extend(format!("250-{}\r\n", self.hostname).as_bytes());
        }
        
        // Extension lines
        for (i, ext) in extensions.iter().enumerate() {
            if i == extensions.len() - 1 {
                response_bytes.extend(format!("250 {}\r\n", ext).as_bytes());
            } else {
                response_bytes.extend(format!("250-{}\r\n", ext).as_bytes());
            }
        }
        
        response_bytes
    }
}

/// Find the end-of-data marker (<CRLF>.<CRLF>) in the buffer
fn find_data_end(buffer: &[u8]) -> Option<usize> {
    // Look for \r\n.\r\n
    let marker = b"\r\n.\r\n";
    
    if buffer.len() < marker.len() {
        return None;
    }

    for i in 0..=buffer.len() - marker.len() {
        if &buffer[i..i + marker.len()] == marker {
            return Some(i);
        }
    }

    // Also check if the data starts with .\r\n (empty message or just the terminator)
    if buffer.starts_with(b".\r\n") {
        return Some(0);
    }

    None
}

/// Remove dot-stuffing from email data (RFC 5321 Section 4.5.2)
fn unstuff_dots(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        // Check for \r\n.. pattern
        if i + 3 < data.len() && &data[i..i + 4] == b"\r\n.." {
            result.extend_from_slice(b"\r\n.");
            i += 4;
        } else if i == 0 && data.len() > 1 && &data[0..2] == b".." {
            // Handle .. at the very start
            result.push(b'.');
            i += 2;
        } else {
            result.push(data[i]);
            i += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greeting() {
        let mut session = SmtpSession::new("mail.example.com", "127.0.0.1");
        let greeting = session.greeting();
        let greeting_str = String::from_utf8_lossy(&greeting);
        assert!(greeting_str.starts_with("220 "));
        assert!(greeting_str.contains("mail.example.com"));
    }

    #[test]
    fn test_ehlo() {
        let mut session = SmtpSession::new("mail.example.com", "127.0.0.1");
        let (response, should_close, _, _) = session.process_input(b"EHLO client.example.com\r\n");
        
        assert!(!should_close);
        assert_eq!(session.state, SmtpState::Greeted);
        assert!(session.is_esmtp);
        
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("250"));
    }

    #[test]
    fn test_mail_transaction() {
        let mut session = SmtpSession::new("mail.example.com", "127.0.0.1");
        
        // EHLO
        session.process_input(b"EHLO client.example.com\r\n");
        
        // MAIL FROM
        let (response, _, _, _) = session.process_input(b"MAIL FROM:<sender@example.com>\r\n");
        assert!(String::from_utf8_lossy(&response).starts_with("250"));
        assert_eq!(session.state, SmtpState::MailFrom);
        
        // RCPT TO
        let (response, _, _, _) = session.process_input(b"RCPT TO:<recipient@example.com>\r\n");
        assert!(String::from_utf8_lossy(&response).starts_with("250"));
        assert_eq!(session.state, SmtpState::RcptTo);
        
        // DATA
        let (response, _, _, _) = session.process_input(b"DATA\r\n");
        assert!(String::from_utf8_lossy(&response).starts_with("354"));
        assert_eq!(session.state, SmtpState::Data);
        
        // Send data with terminator
        let (response, _, _, transaction) = session.process_input(b"Subject: Test\r\n\r\nHello World\r\n.\r\n");
        assert!(String::from_utf8_lossy(&response).starts_with("250"));
        assert!(transaction.is_some());
        assert_eq!(session.state, SmtpState::Greeted);
    }

    #[test]
    fn test_bad_sequence() {
        let mut session = SmtpSession::new("mail.example.com", "127.0.0.1");
        
        // Try MAIL FROM without EHLO first
        let (response, _, _, _) = session.process_input(b"MAIL FROM:<sender@example.com>\r\n");
        assert!(String::from_utf8_lossy(&response).starts_with("503"));
    }

    #[test]
    fn test_quit() {
        let mut session = SmtpSession::new("mail.example.com", "127.0.0.1");
        let (response, should_close, _, _) = session.process_input(b"QUIT\r\n");
        
        assert!(should_close);
        assert!(String::from_utf8_lossy(&response).starts_with("221"));
    }
}
