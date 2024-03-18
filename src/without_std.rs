/// Ensures compatibility with no_std.
pub mod without_std {
    use alloc::string::String;
    pub use core::u32;
    pub use core::u64;

    // Adapt this with whatever printing functionality your host OS requires.

    /// Dummy implementation of Error for no std.
    /// It ensures that the existing code can use it with the same interface
    /// as the Error from std::io::Error.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        error: String,
    }

    impl Error {
        /// New function added for compatibility with the existing code.
        pub fn new<S: Into<String>>(kind: ErrorKind, error: S) -> Error {
            Error {
                kind,
                error: error.into(),
            }
        }
    }

    /// The minimum set of variants to make the dummy ErrorKind work with
    /// the existing code.
    #[derive(Debug)]
    pub enum ErrorKind {
        /// The code only uses this variant.
        Other,
    }
}
