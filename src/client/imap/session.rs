/// IMAP session handler

use super::command::{FetchItems, ImapCommand, SequenceSet};
use super::response;
use crate::client::config::AccountsConfig;
use crate::client::storage::{EmailStorage, MessageFlags, StoredEmail};
use std::sync::Arc;

/// IMAP session state
#[derive(Debug, Clone, PartialEq)]
pub enum ImapState {
    /// Not authenticated
    NotAuthenticated,
    /// Authenticated but no mailbox selected
    Authenticated,
    /// Mailbox selected
    Selected,
    /// Logout requested
    Logout,
}

/// IMAP session for handling mail client connections
pub struct ImapSession {
    pub state: ImapState,
    /// Authenticated user email
    user_email: Option<String>,
    /// Selected mailbox (always "INBOX" for now)
    selected_mailbox: Option<String>,
    /// Server hostname
    hostname: String,
    /// Accounts configuration for authentication
    accounts: AccountsConfig,
    /// Email storage
    storage: Arc<EmailStorage>,
    /// Buffer for incoming data
    buffer: String,
    /// Whether TLS is active
    tls_active: bool,
    /// UID validity for selected mailbox
    uid_validity: u32,
    /// Messages in selected mailbox (cached)
    messages: Vec<StoredEmail>,
    /// Whether the greeting has been sent
    sent_greeting: bool,
    /// AUTHENTICATE in progress (tag, mechanism)
    auth_in_progress: Option<(String, String)>,
}

impl ImapSession {
    pub fn new(hostname: &str, accounts: AccountsConfig, storage: Arc<EmailStorage>, tls_active: bool) -> Self {
        Self {
            state: ImapState::NotAuthenticated,
            user_email: None,
            selected_mailbox: None,
            hostname: hostname.to_string(),
            accounts,
            storage,
            buffer: String::new(),
            tls_active,
            uid_validity: 0,
            messages: Vec::new(),
            sent_greeting: false,
            auth_in_progress: None,
        }
    }

    /// Check if greeting has been sent
    pub fn has_sent_greeting(&self) -> bool {
        self.sent_greeting
    }

    /// Generate the initial greeting
    pub fn greeting(&mut self) -> Vec<u8> {
        self.sent_greeting = true;
        format!("* OK {} IMAP4rev1 Service Ready\r\n", self.hostname).into_bytes()
    }

    /// Process incoming IMAP data
    /// Returns (response_data, should_close, start_tls)
    pub fn process_input(&mut self, data: &[u8]) -> (Vec<u8>, bool, bool) {
        let input = String::from_utf8_lossy(data);
        self.buffer.push_str(&input);

        let mut responses = Vec::new();
        let mut should_close = false;
        let mut start_tls = false;

        // Process complete lines
        while let Some(line_end) = self.buffer.find("\r\n") {
            let line = self.buffer[..line_end].to_string();
            self.buffer.drain(..line_end + 2);

            // Check if we're in the middle of AUTHENTICATE
            if let Some((tag, mechanism)) = self.auth_in_progress.take() {
                let (response, close, tls) = self.handle_auth_response(&tag, &mechanism, &line);
                responses.push(response);
                if close {
                    should_close = true;
                }
                if tls {
                    start_tls = true;
                }
                continue;
            }

            if let Some(cmd) = ImapCommand::parse(&line) {
                let (response, close, tls) = self.handle_command(&cmd);
                responses.push(response);
                if close {
                    should_close = true;
                }
                if tls {
                    start_tls = true;
                }
            } else if !line.is_empty() {
                // Invalid command
                responses.push(format!("* BAD Invalid command: {}\r\n", line));
            }
        }

        (responses.join("").into_bytes(), should_close, start_tls)
    }

    /// Handle a parsed IMAP command
    fn handle_command(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        match cmd.name.as_str() {
            "CAPABILITY" => self.cmd_capability(cmd),
            "NOOP" => self.cmd_noop(cmd),
            "LOGOUT" => self.cmd_logout(cmd),
            "STARTTLS" => self.cmd_starttls(cmd),
            "LOGIN" => self.cmd_login(cmd),
            "AUTHENTICATE" => self.cmd_authenticate(cmd),
            "LIST" => self.cmd_list(cmd),
            "LSUB" => self.cmd_lsub(cmd),
            "SELECT" => self.cmd_select(cmd, false),
            "EXAMINE" => self.cmd_select(cmd, true),
            "CLOSE" => self.cmd_close(cmd),
            "EXPUNGE" => self.cmd_expunge(cmd),
            "FETCH" => self.cmd_fetch(cmd, false),
            "STORE" => self.cmd_store(cmd, false),
            "SEARCH" => self.cmd_search(cmd, false),
            "UID" => self.cmd_uid(cmd),
            "STATUS" => self.cmd_status(cmd),
            _ => (response::bad(&cmd.tag, "Unknown command"), false, false),
        }
    }

    fn cmd_capability(&self, cmd: &ImapCommand) -> (String, bool, bool) {
        let mut resp = response::capability();
        resp.push_str(&response::ok(&cmd.tag, "CAPABILITY completed"));
        (resp, false, false)
    }

    fn cmd_noop(&self, cmd: &ImapCommand) -> (String, bool, bool) {
        (response::ok(&cmd.tag, "NOOP completed"), false, false)
    }

    fn cmd_logout(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        self.state = ImapState::Logout;
        let mut resp = response::bye("IMAP4rev1 Server logging out");
        resp.push_str(&response::ok(&cmd.tag, "LOGOUT completed"));
        (resp, true, false)
    }

    fn cmd_starttls(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.tls_active {
            return (response::bad(&cmd.tag, "TLS already active"), false, false);
        }
        if self.state != ImapState::NotAuthenticated {
            return (response::bad(&cmd.tag, "STARTTLS only allowed before authentication"), false, false);
        }
        
        self.tls_active = true;
        (response::ok(&cmd.tag, "Begin TLS negotiation"), false, true)
    }

    fn cmd_login(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state != ImapState::NotAuthenticated {
            return (response::bad(&cmd.tag, "Already authenticated"), false, false);
        }

        if cmd.args.len() < 2 {
            return (response::bad(&cmd.tag, "Missing username or password"), false, false);
        }

        let username = &cmd.args[0];
        let password = &cmd.args[1];

        if self.accounts.verify_password(username, password) {
            self.user_email = Some(username.to_lowercase());
            self.state = ImapState::Authenticated;
            (response::ok(&cmd.tag, "LOGIN completed"), false, false)
        } else {
            (response::no(&cmd.tag, "[AUTHENTICATIONFAILED] Invalid credentials"), false, false)
        }
    }

    fn cmd_authenticate(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state != ImapState::NotAuthenticated {
            return (response::bad(&cmd.tag, "Already authenticated"), false, false);
        }

        if cmd.args.is_empty() {
            return (response::bad(&cmd.tag, "Missing authentication mechanism"), false, false);
        }

        let mechanism = cmd.args[0].to_uppercase();
        
        match mechanism.as_str() {
            "PLAIN" => {
                // Check if initial response is provided (SASL-IR)
                if cmd.args.len() > 1 {
                    // Initial response provided inline
                    let initial_response = &cmd.args[1];
                    return self.handle_auth_response(&cmd.tag, "PLAIN", initial_response);
                }
                
                // Request client to send credentials with continuation
                self.auth_in_progress = Some((cmd.tag.clone(), "PLAIN".to_string()));
                ("+\r\n".to_string(), false, false)
            }
            _ => (response::no(&cmd.tag, "Unsupported authentication mechanism"), false, false),
        }
    }

    fn handle_auth_response(&mut self, tag: &str, mechanism: &str, response: &str) -> (String, bool, bool) {
        use base64::Engine;
        
        // Client can abort with "*"
        if response == "*" {
            return (response::bad(tag, "AUTHENTICATE aborted"), false, false);
        }

        match mechanism {
            "PLAIN" => {
                // Decode base64 response
                let decoded = match base64::engine::general_purpose::STANDARD.decode(response.trim()) {
                    Ok(d) => d,
                    Err(_) => return (response::no(tag, "[AUTHENTICATIONFAILED] Invalid base64"), false, false),
                };

                // PLAIN format: [authzid]\0authcid\0password
                let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                if parts.len() < 2 {
                    return (response::no(tag, "[AUTHENTICATIONFAILED] Invalid PLAIN format"), false, false);
                }

                // authcid (username) is second element, password is third
                let (username, password) = if parts.len() >= 3 {
                    // authzid, authcid, password
                    (
                        String::from_utf8_lossy(parts[1]).to_string(),
                        String::from_utf8_lossy(parts[2]).to_string(),
                    )
                } else {
                    // authcid, password (no authzid)
                    (
                        String::from_utf8_lossy(parts[0]).to_string(),
                        String::from_utf8_lossy(parts[1]).to_string(),
                    )
                };

                if self.accounts.verify_password(&username, &password) {
                    self.user_email = Some(username.to_lowercase());
                    self.state = ImapState::Authenticated;
                    (response::ok(tag, "AUTHENTICATE completed"), false, false)
                } else {
                    (response::no(tag, "[AUTHENTICATIONFAILED] Invalid credentials"), false, false)
                }
            }
            _ => (response::no(tag, "Unsupported authentication mechanism"), false, false),
        }
    }

    fn cmd_list(&self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state == ImapState::NotAuthenticated {
            return (response::no(&cmd.tag, "Not authenticated"), false, false);
        }

        // Return all standard folders
        let mut resp = response::list_folders();
        resp.push_str(&response::ok(&cmd.tag, "LIST completed"));
        (resp, false, false)
    }

    fn cmd_lsub(&self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state == ImapState::NotAuthenticated {
            return (response::no(&cmd.tag, "Not authenticated"), false, false);
        }

        // Return all folders as subscribed
        let mut resp = String::new();
        resp.push_str(&response::untagged(r#"LSUB (\HasNoChildren) "/" "INBOX""#));
        resp.push_str(&response::untagged(r#"LSUB (\HasNoChildren \Sent) "/" "Sent""#));
        resp.push_str(&response::untagged(r#"LSUB (\HasNoChildren \Drafts) "/" "Drafts""#));
        resp.push_str(&response::untagged(r#"LSUB (\HasNoChildren \Trash) "/" "Trash""#));
        resp.push_str(&response::untagged(r#"LSUB (\HasNoChildren \Junk) "/" "Junk""#));
        resp.push_str(&response::ok(&cmd.tag, "LSUB completed"));
        (resp, false, false)
    }

    fn cmd_select(&mut self, cmd: &ImapCommand, read_only: bool) -> (String, bool, bool) {
        if self.state == ImapState::NotAuthenticated {
            return (response::no(&cmd.tag, "Not authenticated"), false, false);
        }

        let mailbox = if cmd.args.is_empty() {
            "INBOX"
        } else {
            &cmd.args[0]
        };

        // Normalize mailbox name
        let mailbox_upper = mailbox.to_uppercase();
        let valid_folders = ["INBOX", "SENT", "DRAFTS", "TRASH", "JUNK"];
        
        if !valid_folders.contains(&mailbox_upper.as_str()) {
            return (response::no(&cmd.tag, "Mailbox does not exist"), false, false);
        }
        
        // Store the canonical folder name
        let folder_name = match mailbox_upper.as_str() {
            "INBOX" => "INBOX",
            "SENT" => "Sent",
            "DRAFTS" => "Drafts",
            "TRASH" => "Trash",
            "JUNK" => "Junk",
            _ => mailbox,
        };

        // Get mailbox info using sync methods to avoid async deadlock
        let user_email = self.user_email.as_ref().unwrap();
        
        // Only INBOX has actual messages for now, other folders are empty
        let (info, messages) = if mailbox_upper == "INBOX" {
            match self.storage.get_mailbox_info_sync(user_email)
                .and_then(|info| {
                    self.storage.list_messages_sync(user_email).map(|messages| (info, messages))
                }) {
                Ok((info, messages)) => (info, messages),
                Err(_) => {
                    return (response::no(&cmd.tag, "Failed to access mailbox"), false, false);
                }
            }
        } else {
            // Empty folder with default UID validity
            (crate::client::storage::MailboxInfo {
                email: user_email.clone(),
                messages: 0,
                recent: 0,
                unseen: 0,
                uid_validity: 1,
                uid_next: 1,
            }, Vec::new())
        };

        self.uid_validity = info.uid_validity;
        self.messages = messages;
        self.selected_mailbox = Some(folder_name.to_string());
        self.state = ImapState::Selected;

        let unseen = if info.unseen > 0 {
            // Find first unseen message sequence number
            self.messages.iter().position(|m| !m.flags.seen).map(|i| (i + 1) as u32)
        } else {
            None
        };

        let status = response::mailbox_status(
            info.messages,
            info.recent,
            unseen,
            info.uid_validity,
            info.uid_next,
            read_only,
        );

        let cmd_name = if read_only { "EXAMINE" } else { "SELECT" };
        let resp = format!(
            "{}{} OK [READ-{}] {} completed\r\n",
            status,
            cmd.tag,
            if read_only { "ONLY" } else { "WRITE" },
            cmd_name
        );
        (resp, false, false)
    }

    fn cmd_close(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state != ImapState::Selected {
            return (response::no(&cmd.tag, "No mailbox selected"), false, false);
        }

        // Expunge deleted messages silently using sync method
        let user_email = self.user_email.as_ref().unwrap();
        let _ = self.storage.expunge_sync(user_email);

        self.selected_mailbox = None;
        self.messages.clear();
        self.state = ImapState::Authenticated;

        (response::ok(&cmd.tag, "CLOSE completed"), false, false)
    }

    fn cmd_expunge(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state != ImapState::Selected {
            return (response::no(&cmd.tag, "No mailbox selected"), false, false);
        }

        let user_email = self.user_email.as_ref().unwrap();
        
        let result = self.storage.expunge_sync(user_email);

        let mut resp = String::new();
        
        if let Ok(expunged_uids) = result {
            // Report expunged sequence numbers (in reverse order to maintain validity)
            let mut seq_nums: Vec<u32> = Vec::new();
            for uid in &expunged_uids {
                if let Some(pos) = self.messages.iter().position(|m| m.uid == *uid) {
                    seq_nums.push((pos + 1) as u32);
                }
            }
            
            // Remove from cache and report
            self.messages.retain(|m| !expunged_uids.contains(&m.uid));
            
            for seq in seq_nums.iter().rev() {
                resp.push_str(&response::expunge(*seq));
            }
        }

        resp.push_str(&response::ok(&cmd.tag, "EXPUNGE completed"));
        (resp, false, false)
    }

    fn cmd_fetch(&mut self, cmd: &ImapCommand, use_uid: bool) -> (String, bool, bool) {
        if self.state != ImapState::Selected {
            return (response::no(&cmd.tag, "No mailbox selected"), false, false);
        }

        if cmd.args.len() < 2 {
            return (response::bad(&cmd.tag, "Missing sequence set or data items"), false, false);
        }

        let seq_set = match SequenceSet::parse(&cmd.args[0]) {
            Some(s) => s,
            None => return (response::bad(&cmd.tag, "Invalid sequence set"), false, false),
        };

        // Join remaining args for fetch items (handles "(FLAGS BODY[...])")
        let items_str = cmd.args[1..].join(" ");
        let items = FetchItems::parse(&items_str);

        let mut resp = String::new();
        let max_seq = self.messages.len() as u32;
        let user_email = self.user_email.as_ref().unwrap();

        for (idx, msg) in self.messages.iter().enumerate() {
            let seq = (idx + 1) as u32;
            let match_val = if use_uid { msg.uid } else { seq };
            let max_val = if use_uid { 
                self.messages.last().map(|m| m.uid).unwrap_or(0) 
            } else { 
                max_seq 
            };

            if seq_set.iter().any(|s| s.matches(match_val, max_val)) {
                let fetch_resp = self.format_fetch_response(seq, msg, &items, use_uid, user_email);
                resp.push_str(&fetch_resp);
            }
        }

        resp.push_str(&response::ok(&cmd.tag, "FETCH completed"));
        (resp, false, false)
    }

    fn format_fetch_response(
        &self,
        seq: u32,
        msg: &StoredEmail,
        items: &FetchItems,
        use_uid: bool,
        user_email: &str,
    ) -> String {
        let mut parts = Vec::new();

        if items.uid || use_uid {
            parts.push(format!("UID {}", msg.uid));
        }

        if items.flags {
            parts.push(format!("FLAGS {}", msg.flags.to_imap_string()));
        }

        if items.rfc822_size {
            parts.push(format!("RFC822.SIZE {}", msg.size));
        }

        if items.internal_date {
            parts.push(format!("INTERNALDATE {}", response::format_internal_date(&msg.received_at)));
        }

        // For body/envelope/headers, we need to read the actual message
        if items.envelope || items.rfc822_header || items.body_peek.is_some() || items.body.is_some() || items.rfc822 {
            let uid = msg.uid;
            
            let result = self.storage.get_message_by_uid_sync(user_email, uid);

            if let Ok(Some(data)) = result {
                let content = String::from_utf8_lossy(&data);
                let header_end = content.find("\r\n\r\n").or_else(|| content.find("\n\n")).unwrap_or(content.len());
                let headers = &content[..header_end];

                if items.envelope {
                    parts.push(format!("ENVELOPE {}", response::parse_envelope(headers)));
                }

                if items.rfc822_header {
                    let header_bytes = headers.as_bytes();
                    parts.push(format!("RFC822.HEADER {{{}}}\r\n{}", header_bytes.len(), headers));
                }

                if items.rfc822 {
                    parts.push(format!("RFC822 {{{}}}\r\n{}", data.len(), content));
                }

                if let Some(ref section) = items.body_peek {
                    let body_data = self.get_body_section(&content, section);
                    parts.push(format!("BODY[{}] {{{}}}\r\n{}", section, body_data.len(), body_data));
                }

                if let Some(ref section) = items.body {
                    let body_data = self.get_body_section(&content, section);
                    parts.push(format!("BODY[{}] {{{}}}\r\n{}", section, body_data.len(), body_data));
                    // TODO: Mark as \Seen
                }
            }
        }

        response::fetch_response(seq, &parts)
    }

    fn get_body_section(&self, content: &str, section: &str) -> String {
        let section_upper = section.to_uppercase();
        
        if section_upper.is_empty() {
            return content.to_string();
        }

        let header_end = content.find("\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| content.find("\n\n").map(|p| p + 2))
            .unwrap_or(content.len());

        match section_upper.as_str() {
            "HEADER" | "HEADER.FIELDS" => content[..header_end].to_string(),
            "TEXT" => content[header_end..].to_string(),
            _ => content.to_string(),
        }
    }

    fn cmd_store(&mut self, cmd: &ImapCommand, use_uid: bool) -> (String, bool, bool) {
        if self.state != ImapState::Selected {
            return (response::no(&cmd.tag, "No mailbox selected"), false, false);
        }

        if cmd.args.len() < 3 {
            return (response::bad(&cmd.tag, "Missing arguments"), false, false);
        }

        let seq_set = match SequenceSet::parse(&cmd.args[0]) {
            Some(s) => s,
            None => return (response::bad(&cmd.tag, "Invalid sequence set"), false, false),
        };

        let data_item = cmd.args[1].to_uppercase();
        let flags_str = cmd.args[2..].join(" ");
        let new_flags = MessageFlags::from_imap_string(&flags_str);

        let silent = data_item.contains(".SILENT");
        let add_flags = data_item.starts_with("+FLAGS");
        let remove_flags = data_item.starts_with("-FLAGS");

        let mut resp = String::new();
        let max_seq = self.messages.len() as u32;
        let max_uid = self.messages.last().map(|m| m.uid).unwrap_or(0);
        let user_email = self.user_email.as_ref().unwrap().clone();

        for (idx, msg) in self.messages.iter_mut().enumerate() {
            let seq = (idx + 1) as u32;
            let match_val = if use_uid { msg.uid } else { seq };
            let max_val = if use_uid {
                max_uid
            } else {
                max_seq
            };

            if seq_set.iter().any(|s| s.matches(match_val, max_val)) {
                // Update flags
                let mut flags = msg.flags.clone();
                
                if add_flags {
                    if new_flags.seen { flags.seen = true; }
                    if new_flags.answered { flags.answered = true; }
                    if new_flags.flagged { flags.flagged = true; }
                    if new_flags.deleted { flags.deleted = true; }
                    if new_flags.draft { flags.draft = true; }
                } else if remove_flags {
                    if new_flags.seen { flags.seen = false; }
                    if new_flags.answered { flags.answered = false; }
                    if new_flags.flagged { flags.flagged = false; }
                    if new_flags.deleted { flags.deleted = false; }
                    if new_flags.draft { flags.draft = false; }
                } else {
                    flags = new_flags.clone();
                }

                // Save to storage using sync method
                let _ = self.storage.update_flags_sync(&user_email, msg.uid, flags.clone());

                msg.flags = flags;

                if !silent {
                    let mut parts = vec![format!("FLAGS {}", msg.flags.to_imap_string())];
                    if use_uid {
                        parts.insert(0, format!("UID {}", msg.uid));
                    }
                    resp.push_str(&response::fetch_response(seq, &parts));
                }
            }
        }

        resp.push_str(&response::ok(&cmd.tag, "STORE completed"));
        (resp, false, false)
    }

    fn cmd_uid(&mut self, cmd: &ImapCommand) -> (String, bool, bool) {
        if cmd.args.is_empty() {
            return (response::bad(&cmd.tag, "Missing UID subcommand"), false, false);
        }

        let subcmd = cmd.args[0].to_uppercase();
        let subcmd_obj = ImapCommand {
            tag: cmd.tag.clone(),
            name: subcmd.clone(),
            args: cmd.args[1..].to_vec(),
        };

        match subcmd.as_str() {
            "FETCH" => self.cmd_fetch(&subcmd_obj, true),
            "STORE" => self.cmd_store(&subcmd_obj, true),
            "SEARCH" => self.cmd_search(&subcmd_obj, true),
            "EXPUNGE" => self.cmd_expunge(&subcmd_obj),
            _ => (response::bad(&cmd.tag, "Unknown UID subcommand"), false, false),
        }
    }

    fn cmd_search(&self, cmd: &ImapCommand, use_uid: bool) -> (String, bool, bool) {
        if self.state != ImapState::Selected {
            return (response::no(&cmd.tag, "No mailbox selected"), false, false);
        }

        // Parse search criteria - we support a simplified subset
        // Common patterns: ALL, 1:*, NOT DELETED, etc.
        let criteria = cmd.args.join(" ").to_uppercase();
        
        let mut matching_ids: Vec<u32> = Vec::new();
        
        for (idx, msg) in self.messages.iter().enumerate() {
            let seq = (idx + 1) as u32;
            let id = if use_uid { msg.uid } else { seq };
            
            // Check if message matches criteria
            let matches = if criteria.is_empty() || criteria == "ALL" {
                true
            } else if criteria.contains("NOT DELETED") {
                !msg.flags.deleted
            } else if criteria.contains("DELETED") {
                msg.flags.deleted
            } else if criteria.contains("SEEN") && !criteria.contains("UNSEEN") {
                msg.flags.seen
            } else if criteria.contains("UNSEEN") {
                !msg.flags.seen
            } else if criteria.contains("FLAGGED") && !criteria.contains("UNFLAGGED") {
                msg.flags.flagged
            } else if criteria.contains("UNFLAGGED") {
                !msg.flags.flagged
            } else {
                // For sequence set patterns like "1:*" or "1:1", match all for now
                // A more complete implementation would parse the sequence set
                true
            };
            
            if matches {
                matching_ids.push(id);
            }
        }
        
        // Format: * SEARCH 1 2 3 ...
        let ids_str = matching_ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        
        let mut resp = if ids_str.is_empty() {
            response::untagged("SEARCH")
        } else {
            response::untagged(&format!("SEARCH {}", ids_str))
        };
        resp.push_str(&response::ok(&cmd.tag, "SEARCH completed"));
        
        (resp, false, false)
    }

    fn cmd_status(&self, cmd: &ImapCommand) -> (String, bool, bool) {
        if self.state == ImapState::NotAuthenticated {
            return (response::no(&cmd.tag, "Not authenticated"), false, false);
        }

        if cmd.args.is_empty() {
            return (response::bad(&cmd.tag, "Missing mailbox name"), false, false);
        }

        let mailbox = &cmd.args[0];
        if mailbox.to_uppercase() != "INBOX" {
            return (response::no(&cmd.tag, "Mailbox does not exist"), false, false);
        }

        let user_email = self.user_email.as_ref().unwrap();
        let result = self.storage.get_mailbox_info_sync(user_email);

        match result {
            Ok(info) => {
                let mut items = Vec::new();
                
                let status_items = if cmd.args.len() > 1 {
                    cmd.args[1..].join(" ").to_uppercase()
                } else {
                    "MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY".to_string()
                };

                if status_items.contains("MESSAGES") {
                    items.push(format!("MESSAGES {}", info.messages));
                }
                if status_items.contains("RECENT") {
                    items.push(format!("RECENT {}", info.recent));
                }
                if status_items.contains("UNSEEN") {
                    items.push(format!("UNSEEN {}", info.unseen));
                }
                if status_items.contains("UIDNEXT") {
                    items.push(format!("UIDNEXT {}", info.uid_next));
                }
                if status_items.contains("UIDVALIDITY") {
                    items.push(format!("UIDVALIDITY {}", info.uid_validity));
                }

                let mut resp = response::untagged(&format!("STATUS INBOX ({})", items.join(" ")));
                resp.push_str(&response::ok(&cmd.tag, "STATUS completed"));
                (resp, false, false)
            }
            _ => {
                (response::no(&cmd.tag, "Failed to get status"), false, false)
            }
        }
    }
}
