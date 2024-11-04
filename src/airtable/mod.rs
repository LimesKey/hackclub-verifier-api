pub mod fetch;
pub mod types;
pub mod update;

pub use fetch::fetch_submissions;
pub use types::{Fields, Record};
pub use update::update_submission; // Re-export types for easy access
