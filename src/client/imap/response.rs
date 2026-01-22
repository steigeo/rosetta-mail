/// IMAP response formatting

/// Format a tagged OK response
pub fn ok(tag: &str, message: &str) -> String {
    format!("{} OK {}\r\n", tag, message)
}

/// Format a tagged NO response
pub fn no(tag: &str, message: &str) -> String {
    format!("{} NO {}\r\n", tag, message)
}

/// Format a tagged BAD response
pub fn bad(tag: &str, message: &str) -> String {
    format!("{} BAD {}\r\n", tag, message)
}

/// Format an untagged response
pub fn untagged(response: &str) -> String {
    format!("* {}\r\n", response)
}

/// Format a BYE response
pub fn bye(message: &str) -> String {
    format!("* BYE {}\r\n", message)
}

/// Format a capability response
pub fn capability() -> String {
    untagged("CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS")
}

/// Format list responses for all standard folders
pub fn list_folders() -> String {
    let mut resp = String::new();
    resp.push_str(&untagged(r#"LIST (\HasNoChildren) "/" "INBOX""#));
    resp.push_str(&untagged(r#"LIST (\HasNoChildren \Sent) "/" "Sent""#));
    resp.push_str(&untagged(r#"LIST (\HasNoChildren \Drafts) "/" "Drafts""#));
    resp.push_str(&untagged(r#"LIST (\HasNoChildren \Trash) "/" "Trash""#));
    resp.push_str(&untagged(r#"LIST (\HasNoChildren \Junk) "/" "Junk""#));
    resp
}

/// Format mailbox status for SELECT/EXAMINE
pub fn mailbox_status(
    exists: u32,
    recent: u32,
    unseen: Option<u32>,
    uid_validity: u32,
    uid_next: u32,
    _read_only: bool,
) -> String {
    let mut response = String::new();
    
    response.push_str(&untagged(&format!("{} EXISTS", exists)));
    response.push_str(&untagged(&format!("{} RECENT", recent)));
    response.push_str(&untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)"));
    response.push_str(&untagged("OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)]"));
    
    if let Some(first_unseen) = unseen {
        response.push_str(&untagged(&format!("OK [UNSEEN {}]", first_unseen)));
    }
    
    response.push_str(&untagged(&format!("OK [UIDVALIDITY {}]", uid_validity)));
    response.push_str(&untagged(&format!("OK [UIDNEXT {}]", uid_next)));
    
    response
}

/// Format a FETCH response line
pub fn fetch_response(seq: u32, items: &[String]) -> String {
    untagged(&format!("{} FETCH ({})", seq, items.join(" ")))
}

/// Format an EXPUNGE response
pub fn expunge(seq: u32) -> String {
    untagged(&format!("{} EXPUNGE", seq))
}

/// Format a literal string with length prefix
#[allow(dead_code)]
pub fn literal(data: &[u8]) -> String {
    format!("{{{}}}\r\n", data.len())
}

/// Escape a string for IMAP (wrap in quotes if needed)
pub fn quoted_string(s: &str) -> String {
    if s.is_empty() || s.contains(' ') || s.contains('"') || s.contains('\\') {
        // Need to escape
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("\"{}\"", escaped)
    } else {
        format!("\"{}\"", s)
    }
}

/// Format NIL for empty values
pub fn nil() -> &'static str {
    "NIL"
}

/// Parse email headers to extract common fields for ENVELOPE
pub fn parse_envelope(headers: &str) -> String {
    let mut date = String::new();
    let mut subject = String::new();
    let mut from = String::new();
    let mut sender = String::new();
    let mut reply_to = String::new();
    let mut to = String::new();
    let mut cc = String::new();
    let mut bcc = String::new();
    let mut in_reply_to = String::new();
    let mut message_id = String::new();

    let mut current_header = String::new();
    let mut current_value = String::new();

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            current_value.push(' ');
            current_value.push_str(line.trim());
        } else if let Some(colon_pos) = line.find(':') {
            // Save previous header
            if !current_header.is_empty() {
                save_header_value(
                    &current_header,
                    &current_value,
                    &mut date,
                    &mut subject,
                    &mut from,
                    &mut sender,
                    &mut reply_to,
                    &mut to,
                    &mut cc,
                    &mut bcc,
                    &mut in_reply_to,
                    &mut message_id,
                );
            }
            current_header = line[..colon_pos].to_lowercase();
            current_value = line[colon_pos + 1..].trim().to_string();
        }
    }

    // Save last header
    if !current_header.is_empty() {
        save_header_value(
            &current_header,
            &current_value,
            &mut date,
            &mut subject,
            &mut from,
            &mut sender,
            &mut reply_to,
            &mut to,
            &mut cc,
            &mut bcc,
            &mut in_reply_to,
            &mut message_id,
        );
    }

    // If sender is empty, use from
    if sender.is_empty() {
        sender = from.clone();
    }
    if reply_to.is_empty() {
        reply_to = from.clone();
    }

    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        if date.is_empty() { nil().to_string() } else { quoted_string(&date) },
        if subject.is_empty() { nil().to_string() } else { quoted_string(&subject) },
        format_address_list(&from),
        format_address_list(&sender),
        format_address_list(&reply_to),
        format_address_list(&to),
        format_address_list(&cc),
        format_address_list(&bcc),
        if in_reply_to.is_empty() { nil().to_string() } else { quoted_string(&in_reply_to) },
        if message_id.is_empty() { nil().to_string() } else { quoted_string(&message_id) },
    )
}

fn save_header_value(
    header: &str,
    value: &str,
    date: &mut String,
    subject: &mut String,
    from: &mut String,
    sender: &mut String,
    reply_to: &mut String,
    to: &mut String,
    cc: &mut String,
    bcc: &mut String,
    in_reply_to: &mut String,
    message_id: &mut String,
) {
    match header {
        "date" => *date = value.to_string(),
        "subject" => *subject = value.to_string(),
        "from" => *from = value.to_string(),
        "sender" => *sender = value.to_string(),
        "reply-to" => *reply_to = value.to_string(),
        "to" => *to = value.to_string(),
        "cc" => *cc = value.to_string(),
        "bcc" => *bcc = value.to_string(),
        "in-reply-to" => *in_reply_to = value.to_string(),
        "message-id" => *message_id = value.to_string(),
        _ => {}
    }
}

/// Format an address list for ENVELOPE (simplified - just parses "Name <email>" format)
fn format_address_list(addr: &str) -> String {
    if addr.is_empty() {
        return nil().to_string();
    }

    // Very simplified parsing - real implementation would handle RFC 5322 fully
    let addresses: Vec<String> = addr
        .split(',')
        .map(|a| format_single_address(a.trim()))
        .collect();

    format!("({})", addresses.join(" "))
}

fn format_single_address(addr: &str) -> String {
    // Try to parse "Display Name <email@domain>"
    if let Some(lt_pos) = addr.find('<') {
        if let Some(gt_pos) = addr.find('>') {
            let name = addr[..lt_pos].trim().trim_matches('"');
            let email = &addr[lt_pos + 1..gt_pos];
            
            if let Some(at_pos) = email.find('@') {
                let local = &email[..at_pos];
                let domain = &email[at_pos + 1..];
                
                return format!(
                    "({} NIL {} {})",
                    if name.is_empty() { nil().to_string() } else { quoted_string(name) },
                    quoted_string(local),
                    quoted_string(domain)
                );
            }
        }
    }
    
    // Just an email address
    if let Some(at_pos) = addr.find('@') {
        let local = &addr[..at_pos];
        let domain = &addr[at_pos + 1..];
        
        return format!(
            "(NIL NIL {} {})",
            quoted_string(local),
            quoted_string(domain)
        );
    }

    // Can't parse - return NIL
    nil().to_string()
}

/// Format internal date
pub fn format_internal_date(date: &chrono::DateTime<chrono::Utc>) -> String {
    date.format("\"%d-%b-%Y %H:%M:%S +0000\"").to_string()
}
