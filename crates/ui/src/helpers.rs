//! Helper functions for the UI

use arboard::Clipboard;

/// Copy text to clipboard
pub fn copy_to_clipboard(text: &str) -> bool {
    if let Ok(mut clipboard) = Clipboard::new() {
        clipboard.set_text(text).is_ok()
    } else {
        false
    }
}
