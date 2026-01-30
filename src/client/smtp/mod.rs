/// SMTP Server implementation according to RFC 5321
mod command;
pub mod mailer;
pub mod outbound;
pub mod outbox;
mod response;
pub mod security;
pub mod sender;
mod session;
mod transaction;

pub use command::{parse_command, SmtpCommand};
pub use mailer::{Mailer, MailerConfig, MailerError};
pub use outbound::{SmtpClient, SmtpClientError, SmtpReply};
pub use outbox::{create_shared_outbox, generate_bounce_message, Outbox, QueuedEmail, SharedOutbox};
pub use response::SmtpResponse;
pub use sender::{OutboundSender, PendingOutbound, SharedPendingConnections};
pub use session::{SmtpResult, SmtpSession, SmtpState};
pub use transaction::MailTransaction;
