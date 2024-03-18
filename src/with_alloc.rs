#[macro_use]
extern crate alloc;

/// Re-export of the alloc crate contents for use in no_std environment.
pub mod with_alloc {
    pub use alloc::{boxed, string, vec};
    pub use alloc::string::String;
    pub use alloc::string::ToString;

    /// Re-export of the collections defined in the alloc crate for use in
    /// no_std environment.
    pub mod collections {
        pub use alloc::vec::Vec;
        pub use alloc::collections::BTreeMap as HashMap;
    }
}
