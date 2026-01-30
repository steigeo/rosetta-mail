/// Logging utilities with verbose mode support
/// 
/// Set VERBOSE=1 or use --verbose flag to enable verbose logging

use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbose flag
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable verbose logging
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::SeqCst);
}

/// Check if verbose logging is enabled
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::SeqCst)
}

/// Log a message only in verbose mode
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {
        if $crate::client::logging::is_verbose() {
            println!($($arg)*);
        }
    };
}

/// Log an error/warning message (always shown)
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

/// Log an important info message (always shown)
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}
