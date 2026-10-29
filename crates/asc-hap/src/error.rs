use thiserror::Error;

/// Recoverable HAP or ABC failure.
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to {action} {path}: {source}")]
    IoPath {
        action: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Abc(#[from] asc_abc::Error),
    #[error(transparent)]
    Decompile(#[from] asc_abc_dec::Error),
    /// The file has no ZIP end-of-central-directory record.
    #[error("EOCD not found")]
    NoEocd,
    #[error("{0}")]
    Message(String),
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}
