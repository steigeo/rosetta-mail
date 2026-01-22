pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/tunnel.rs"));
}

pub mod client;
pub mod server;

pub use proto::*;
