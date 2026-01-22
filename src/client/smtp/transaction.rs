/// Mail transaction data
#[derive(Debug, Clone, Default)]
pub struct MailTransaction {
    /// Reverse path (MAIL FROM address)
    pub mail_from: String,
    /// Forward paths (RCPT TO addresses)
    pub rcpt_to: Vec<String>,
    /// Email data (headers + body)
    pub data: Vec<u8>,
    /// Whether this is an outbound message (submission port)
    pub is_outbound: bool,
    /// Authenticated user who sent this (for outbound)
    pub authenticated_user: Option<String>,
}

impl MailTransaction {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.mail_from.clear();
        self.rcpt_to.clear();
        self.data.clear();
    }

    pub fn set_mail_from(&mut self, address: String) {
        self.mail_from = address;
    }

    pub fn add_rcpt_to(&mut self, address: String) {
        self.rcpt_to.push(address);
    }

    pub fn append_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn has_mail_from(&self) -> bool {
        !self.mail_from.is_empty()
    }

    pub fn has_recipients(&self) -> bool {
        !self.rcpt_to.is_empty()
    }

    /// Get the email data as a string (lossy UTF-8 conversion)
    pub fn data_as_string(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }
}
