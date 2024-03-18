pub mod with_std {
    pub use std::io::{Error, ErrorKind};
    pub use std::println;
    pub use std::string::String;
    pub use std::string::ToString;
    pub use std::{u32, u64};
    pub use std::vec;
    pub mod collections {
        pub use std::collections::{HashMap, HashSet, BTreeMap};
    }
}
