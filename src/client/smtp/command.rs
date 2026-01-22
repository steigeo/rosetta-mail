/// SMTP Commands according to RFC 5321

#[derive(Debug, Clone, PartialEq)]
pub enum SmtpCommand {
    /// HELO <domain>
    Helo(String),
    /// EHLO <domain>
    Ehlo(String),
    /// MAIL FROM:<reverse-path> [SP <mail-parameters>]
    MailFrom {
        address: String,
        parameters: Vec<String>,
    },
    /// RCPT TO:<forward-path> [SP <rcpt-parameters>]
    RcptTo {
        address: String,
        parameters: Vec<String>,
    },
    /// DATA
    Data,
    /// RSET
    Rset,
    /// STARTTLS
    StartTls,
    /// AUTH mechanism [initial-response]
    Auth {
        mechanism: String,
        initial_response: Option<String>,
    },
    /// VRFY <string>
    Vrfy(String),
    /// EXPN <string>
    Expn(String),
    /// HELP [<string>]
    Help(Option<String>),
    /// NOOP [<string>]
    Noop(Option<String>),
    /// QUIT
    Quit,
    /// Unknown command
    Unknown(String),
}

/// Parse an SMTP command from a line of input
pub fn parse_command(input: &str) -> SmtpCommand {
    let input = input.trim_end_matches(|c| c == '\r' || c == '\n');

    // Split into command and arguments
    let (cmd, args) = match input.find(' ') {
        Some(pos) => (&input[..pos], input[pos + 1..].trim()),
        None => (input, ""),
    };

    match cmd.to_uppercase().as_str() {
        "HELO" => {
            if args.is_empty() {
                SmtpCommand::Unknown(input.to_string())
            } else {
                SmtpCommand::Helo(args.to_string())
            }
        }
        "EHLO" => {
            if args.is_empty() {
                SmtpCommand::Unknown(input.to_string())
            } else {
                SmtpCommand::Ehlo(args.to_string())
            }
        }
        "MAIL" => parse_mail_from(args),
        "RCPT" => parse_rcpt_to(args),
        "DATA" => SmtpCommand::Data,
        "RSET" => SmtpCommand::Rset,
        "STARTTLS" => SmtpCommand::StartTls,
        "AUTH" => parse_auth(args),
        "VRFY" => SmtpCommand::Vrfy(args.to_string()),
        "EXPN" => SmtpCommand::Expn(args.to_string()),
        "HELP" => {
            if args.is_empty() {
                SmtpCommand::Help(None)
            } else {
                SmtpCommand::Help(Some(args.to_string()))
            }
        }
        "NOOP" => {
            if args.is_empty() {
                SmtpCommand::Noop(None)
            } else {
                SmtpCommand::Noop(Some(args.to_string()))
            }
        }
        "QUIT" => SmtpCommand::Quit,
        _ => SmtpCommand::Unknown(input.to_string()),
    }
}

/// Parse MAIL FROM command
fn parse_mail_from(args: &str) -> SmtpCommand {
    // Expected format: FROM:<address> [parameters]
    let args_upper = args.to_uppercase();
    if !args_upper.starts_with("FROM:") {
        return SmtpCommand::Unknown(format!("MAIL {}", args));
    }

    let rest = &args[5..]; // Skip "FROM:"
    match parse_address_and_params(rest) {
        Some((address, parameters)) => SmtpCommand::MailFrom {
            address,
            parameters,
        },
        None => SmtpCommand::Unknown(format!("MAIL {}", args)),
    }
}

/// Parse AUTH command
/// Format: AUTH mechanism [initial-response]
/// initial-response can be "=" for empty or base64-encoded data
fn parse_auth(args: &str) -> SmtpCommand {
    let parts: Vec<&str> = args.splitn(2, ' ').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return SmtpCommand::Unknown(format!("AUTH {}", args));
    }

    let mechanism = parts[0].to_uppercase();
    let initial_response = if parts.len() > 1 && !parts[1].is_empty() {
        Some(parts[1].to_string())
    } else {
        None
    };

    SmtpCommand::Auth {
        mechanism,
        initial_response,
    }
}

/// Parse RCPT TO command
fn parse_rcpt_to(args: &str) -> SmtpCommand {
    // Expected format: TO:<address> [parameters]
    let args_upper = args.to_uppercase();
    if !args_upper.starts_with("TO:") {
        return SmtpCommand::Unknown(format!("RCPT {}", args));
    }

    let rest = &args[3..]; // Skip "TO:"
    match parse_address_and_params(rest) {
        Some((address, parameters)) => SmtpCommand::RcptTo {
            address,
            parameters,
        },
        None => SmtpCommand::Unknown(format!("RCPT {}", args)),
    }
}

/// Parse an address in angle brackets and any following parameters
fn parse_address_and_params(input: &str) -> Option<(String, Vec<String>)> {
    let input = input.trim();

    if !input.starts_with('<') {
        return None;
    }

    let end_bracket = input.find('>')?;
    let address = input[1..end_bracket].to_string();

    let rest = input[end_bracket + 1..].trim();
    let parameters: Vec<String> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split_whitespace().map(|s| s.to_string()).collect()
    };

    Some((address, parameters))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_helo() {
        assert_eq!(
            parse_command("HELO example.com\r\n"),
            SmtpCommand::Helo("example.com".to_string())
        );
    }

    #[test]
    fn test_parse_ehlo() {
        assert_eq!(
            parse_command("EHLO mail.example.org"),
            SmtpCommand::Ehlo("mail.example.org".to_string())
        );
    }

    #[test]
    fn test_parse_mail_from() {
        assert_eq!(
            parse_command("MAIL FROM:<sender@example.com>"),
            SmtpCommand::MailFrom {
                address: "sender@example.com".to_string(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn test_parse_mail_from_with_params() {
        assert_eq!(
            parse_command("MAIL FROM:<sender@example.com> SIZE=1024"),
            SmtpCommand::MailFrom {
                address: "sender@example.com".to_string(),
                parameters: vec!["SIZE=1024".to_string()],
            }
        );
    }

    #[test]
    fn test_parse_rcpt_to() {
        assert_eq!(
            parse_command("RCPT TO:<recipient@example.com>"),
            SmtpCommand::RcptTo {
                address: "recipient@example.com".to_string(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn test_parse_data() {
        assert_eq!(parse_command("DATA\r\n"), SmtpCommand::Data);
    }

    #[test]
    fn test_parse_quit() {
        assert_eq!(parse_command("QUIT"), SmtpCommand::Quit);
    }

    #[test]
    fn test_parse_unknown() {
        match parse_command("INVALID") {
            SmtpCommand::Unknown(_) => (),
            _ => panic!("Expected Unknown command"),
        }
    }
}
