use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DHCP parse error: {0}")]
    Parse(String),

    #[error("packet too large: {size} exceeds limit {limit}")]
    PacketTooLarge { size: usize, limit: usize },

    #[error("giaddr spoof detected: {0}")]
    GiaddrSpoof(String),

    #[error("Option 82 echo mismatch")]
    Option82Mismatch,

    #[error("VSS not supported by server")]
    VssNotSupported,

    #[error("VPN not configured: {0}")]
    VpnNotConfigured(String),

    #[error("DPD stale packet detected")]
    DpdStalePacket,

    #[error("config error: {0}")]
    Config(String),

    #[error("transport error: {0}")]
    Transport(String),
}

pub type RelayResult<T> = Result<T, RelayError>;
