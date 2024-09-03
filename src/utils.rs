use std::panic;

// Function to set up the global panic hook
pub fn set_global_panic_hook() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}
