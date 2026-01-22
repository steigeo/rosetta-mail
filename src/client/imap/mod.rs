/// IMAP server implementation (RFC 3501 subset)
/// 
/// Supports minimal IMAP4rev1 commands:
/// - CAPABILITY, NOOP, LOGOUT
/// - LOGIN (authentication)
/// - LIST, SELECT, EXAMINE
/// - FETCH (headers, body, flags, envelope)
/// - STORE (flags)
/// - CLOSE, EXPUNGE
/// - UID variants of FETCH, STORE

mod session;
mod command;
mod response;

pub use session::ImapSession;
