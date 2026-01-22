use crate::proto::TunnelMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Represents an active TCP connection
pub struct TcpConnection {
    pub tx: mpsc::Sender<Vec<u8>>,
}

/// Represents a connected websocket client
pub struct WsClient {
    pub tx: mpsc::Sender<TunnelMessage>,
    pub connections: HashMap<u64, TcpConnection>,
}

/// Shared state: map of client ID to client
pub type ClientsMap = Arc<RwLock<HashMap<u64, WsClient>>>;

/// Shared state: currently active client ID
pub type ActiveClientId = Arc<RwLock<Option<u64>>>;
