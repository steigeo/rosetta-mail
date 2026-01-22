/// IMAP command parsing

/// Parsed IMAP command
#[derive(Debug, Clone)]
pub struct ImapCommand {
    pub tag: String,
    pub name: String,
    pub args: Vec<String>,
}

impl ImapCommand {
    /// Parse an IMAP command line
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut in_literal = false;
        let mut chars = line.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '"' if !in_literal => {
                    in_quotes = !in_quotes;
                    // Don't include quotes in the output
                }
                ' ' if !in_quotes && !in_literal => {
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                }
                '{' if !in_quotes => {
                    // Literal syntax {n} - just store the marker for now
                    current.push(c);
                    in_literal = true;
                }
                '}' if in_literal => {
                    current.push(c);
                    in_literal = false;
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.is_empty() {
            parts.push(current);
        }

        if parts.len() < 2 {
            return None;
        }

        let tag = parts.remove(0);
        let name = parts.remove(0).to_uppercase();

        Some(ImapCommand {
            tag,
            name,
            args: parts,
        })
    }
}

/// Sequence set for FETCH/STORE commands
#[derive(Debug, Clone)]
pub enum SequenceSet {
    Single(u32),
    Range(u32, u32),
    All,
}

impl SequenceSet {
    /// Parse a sequence set string (e.g., "1", "1:5", "1:*", "*")
    pub fn parse(s: &str) -> Option<Vec<Self>> {
        let mut result = Vec::new();
        
        for part in s.split(',') {
            let part = part.trim();
            if part == "*" {
                result.push(SequenceSet::All);
            } else if part.contains(':') {
                let mut range = part.split(':');
                let start = range.next()?;
                let end = range.next()?;
                
                let start_num = if start == "*" {
                    u32::MAX
                } else {
                    start.parse().ok()?
                };
                
                let end_num = if end == "*" {
                    u32::MAX
                } else {
                    end.parse().ok()?
                };
                
                result.push(SequenceSet::Range(start_num, end_num));
            } else {
                let num = part.parse().ok()?;
                result.push(SequenceSet::Single(num));
            }
        }
        
        Some(result)
    }

    /// Check if a sequence number matches this set
    pub fn matches(&self, seq: u32, max: u32) -> bool {
        match self {
            SequenceSet::Single(n) => seq == *n || (*n == u32::MAX && seq == max),
            SequenceSet::Range(start, end) => {
                let actual_start = if *start == u32::MAX { max } else { *start };
                let actual_end = if *end == u32::MAX { max } else { *end };
                seq >= actual_start && seq <= actual_end
            }
            SequenceSet::All => true,
        }
    }
}

/// FETCH data items to retrieve
#[derive(Debug, Clone, Default)]
pub struct FetchItems {
    pub flags: bool,
    pub envelope: bool,
    pub body_structure: bool,
    pub body_peek: Option<String>,  // Section specifier
    pub body: Option<String>,        // Section specifier (sets \Seen)
    pub rfc822_size: bool,
    pub rfc822_header: bool,
    pub rfc822_text: bool,
    pub rfc822: bool,
    pub uid: bool,
    pub internal_date: bool,
}

impl FetchItems {
    /// Parse FETCH item list like "(FLAGS BODY[HEADER])" or "ALL"
    pub fn parse(s: &str) -> Self {
        let mut items = FetchItems::default();
        let s = s.trim();
        
        // Handle macros
        match s.to_uppercase().as_str() {
            "ALL" => {
                items.flags = true;
                items.internal_date = true;
                items.rfc822_size = true;
                items.envelope = true;
                return items;
            }
            "FAST" => {
                items.flags = true;
                items.internal_date = true;
                items.rfc822_size = true;
                return items;
            }
            "FULL" => {
                items.flags = true;
                items.internal_date = true;
                items.rfc822_size = true;
                items.envelope = true;
                items.body_structure = true;
                return items;
            }
            _ => {}
        }
        
        // Remove parentheses if present
        let s = s.trim_start_matches('(').trim_end_matches(')');
        
        // Parse individual items
        let s_upper = s.to_uppercase();
        
        if s_upper.contains("FLAGS") {
            items.flags = true;
        }
        if s_upper.contains("ENVELOPE") {
            items.envelope = true;
        }
        if s_upper.contains("BODYSTRUCTURE") {
            items.body_structure = true;
        }
        if s_upper.contains("RFC822.SIZE") {
            items.rfc822_size = true;
        }
        if s_upper.contains("RFC822.HEADER") {
            items.rfc822_header = true;
        }
        if s_upper.contains("RFC822.TEXT") {
            items.rfc822_text = true;
        }
        if s_upper.contains("INTERNALDATE") {
            items.internal_date = true;
        }
        if s_upper.contains("UID") {
            items.uid = true;
        }
        
        // Parse BODY.PEEK[section] or BODY[section]
        if let Some(pos) = s_upper.find("BODY.PEEK[") {
            if let Some(end) = s[pos + 10..].find(']') {
                items.body_peek = Some(s[pos + 10..pos + 10 + end].to_string());
            }
        } else if let Some(pos) = s_upper.find("BODY[") {
            if let Some(end) = s[pos + 5..].find(']') {
                items.body = Some(s[pos + 5..pos + 5 + end].to_string());
            }
        }
        
        // RFC822 (full message)
        if s_upper.contains("RFC822") && !s_upper.contains("RFC822.") {
            items.rfc822 = true;
        }
        
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command() {
        let cmd = ImapCommand::parse("A001 LOGIN user@example.com password").unwrap();
        assert_eq!(cmd.tag, "A001");
        assert_eq!(cmd.name, "LOGIN");
        assert_eq!(cmd.args, vec!["user@example.com", "password"]);
    }

    #[test]
    fn test_parse_quoted() {
        let cmd = ImapCommand::parse(r#"A001 LOGIN "user name" "pass word""#).unwrap();
        assert_eq!(cmd.args, vec!["user name", "pass word"]);
    }

    #[test]
    fn test_sequence_set() {
        let sets = SequenceSet::parse("1:5").unwrap();
        assert!(matches!(&sets[0], SequenceSet::Range(1, 5)));
        
        let sets = SequenceSet::parse("*").unwrap();
        assert!(matches!(&sets[0], SequenceSet::All));
    }
}
