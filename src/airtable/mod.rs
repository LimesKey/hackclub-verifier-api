pub mod fetch;
pub mod update;
pub mod types;

pub use fetch::fetch_submissions;
pub use update::update_submission;
pub use types::{Record, Fields};  // Re-export types for easy access