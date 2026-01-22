/// SMTP response codes and messages according to RFC 5321
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub message: String,
    pub is_multiline: bool,
}

impl SmtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            is_multiline: false,
        }
    }

    pub fn multiline(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            is_multiline: true,
        }
    }

    /// Format response for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{} {}\r\n", self.code, self.message).into_bytes()
    }

    /// Format multiline response (for EHLO)
    pub fn to_bytes_multiline(&self, lines: &[&str], last_line: &str) -> Vec<u8> {
        let mut result = String::new();
        for line in lines {
            result.push_str(&format!("{}-{}\r\n", self.code, line));
        }
        result.push_str(&format!("{} {}\r\n", self.code, last_line));
        result.into_bytes()
    }

    // === Standard SMTP Responses ===

    /// 220 - Service ready
    pub fn service_ready(domain: &str) -> Self {
        Self::new(220, format!("{} ESMTP Service Ready", domain))
    }

    /// 221 - Service closing
    pub fn service_closing(domain: &str) -> Self {
        Self::new(221, format!("{} Service closing transmission channel", domain))
    }

    /// 250 - Requested action okay
    pub fn ok(message: impl Into<String>) -> Self {
        Self::new(250, message)
    }

    /// 354 - Start mail input
    pub fn start_mail_input() -> Self {
        Self::new(354, "Start mail input; end with <CRLF>.<CRLF>")
    }

    /// 421 - Service not available
    pub fn service_unavailable(domain: &str) -> Self {
        Self::new(421, format!("{} Service not available, closing transmission channel", domain))
    }

    /// 450 - Mailbox unavailable (temporary)
    pub fn mailbox_unavailable_temp(mailbox: &str) -> Self {
        Self::new(450, format!("Requested mail action not taken: mailbox {} unavailable", mailbox))
    }

    /// 451 - Local error in processing
    pub fn local_error() -> Self {
        Self::new(451, "Requested action aborted: local error in processing")
    }

    /// 452 - Insufficient storage
    pub fn insufficient_storage() -> Self {
        Self::new(452, "Requested action not taken: insufficient system storage")
    }

    /// 500 - Syntax error, command unrecognized
    pub fn syntax_error() -> Self {
        Self::new(500, "Syntax error, command unrecognized")
    }

    /// 501 - Syntax error in parameters
    pub fn syntax_error_params() -> Self {
        Self::new(501, "Syntax error in parameters or arguments")
    }

    /// 502 - Command not implemented
    pub fn not_implemented() -> Self {
        Self::new(502, "Command not implemented")
    }

    /// 503 - Bad sequence of commands
    pub fn bad_sequence() -> Self {
        Self::new(503, "Bad sequence of commands")
    }

    /// 504 - Parameter not implemented
    pub fn param_not_implemented() -> Self {
        Self::new(504, "Command parameter not implemented")
    }

    /// 550 - Mailbox unavailable (permanent)
    pub fn mailbox_unavailable(reason: &str) -> Self {
        Self::new(550, format!("Requested action not taken: {}", reason))
    }

    /// 551 - User not local
    pub fn user_not_local(forward_path: &str) -> Self {
        Self::new(551, format!("User not local; please try <{}>", forward_path))
    }

    /// 552 - Exceeded storage allocation
    pub fn storage_exceeded() -> Self {
        Self::new(552, "Requested mail action aborted: exceeded storage allocation")
    }

    /// 553 - Mailbox name not allowed
    pub fn mailbox_name_not_allowed() -> Self {
        Self::new(553, "Requested action not taken: mailbox name not allowed")
    }

    /// 554 - Transaction failed
    pub fn transaction_failed() -> Self {
        Self::new(554, "Transaction failed")
    }

    // === Authentication responses ===
    
    /// 235 - Authentication successful
    pub fn auth_successful() -> Self {
        Self::new(235, "2.7.0 Authentication successful")
    }

    /// 334 - Authentication continuation (base64 encoded challenge)
    pub fn auth_continue(challenge: &str) -> Self {
        Self::new(334, challenge)
    }

    /// 530 - Authentication required
    pub fn auth_required() -> Self {
        Self::new(530, "5.7.0 Authentication required")
    }

    /// 534 - Authentication mechanism too weak
    pub fn auth_too_weak() -> Self {
        Self::new(534, "5.7.9 Authentication mechanism too weak")
    }

    /// 535 - Authentication credentials invalid
    pub fn auth_failed() -> Self {
        Self::new(535, "5.7.8 Authentication credentials invalid")
    }

    /// 538 - Encryption required for authentication
    pub fn auth_encryption_required() -> Self {
        Self::new(538, "5.7.11 Encryption required for requested authentication mechanism")
    }
}
