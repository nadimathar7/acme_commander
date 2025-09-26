//! 统一错误处理模块
//! 定义 ACME Commander 的所有错误类型

use thiserror::Error;

/// ACME Commander 主要错误类型
#[derive(Debug, Error)]
pub enum AcmeError {
    /// 认证相关错误
    #[error("认证错误: {0}")]
    Auth(#[from] AuthError),
    
    /// ACME 协议错误
    #[error("ACME 协议错误: {0}")]
    AcmeProtocolError(String),
    
    /// 协议错误
    #[error("协议错误: {0}")]
    ProtocolError(String),
    
    /// 证书相关错误
    #[error("证书错误: {0}")]
    Certificate(#[from] CertificateError),
    
    /// DNS 相关错误
    #[error("DNS 错误: {0}")]
    Dns(#[from] DnsError),
    
    /// 加密相关错误
    #[error("加密错误: {0}")]
    Crypto(#[from] CryptoError),
    
    /// 加密错误变体
    #[error("加密错误: {0}")]
    CryptoError(String),
    
    /// 网络请求错误
    #[error("HTTP 请求错误: {0}")]
    Http(#[from] reqwest::Error),
    
    /// HTTP 错误变体
    #[error("HTTP 错误: {0}")]
    HttpError(String),
    
    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    
    /// JSON 序列化错误
    #[error("JSON 错误: {0}")]
    Json(#[from] serde_json::Error),
    
    /// JSON 错误变体
    #[error("JSON 错误: {0}")]
    JsonError(String),
    
    /// 配置错误
    #[error("配置错误: {0}")]
    Config(String),
    
    /// 配置错误变体
    #[error("配置错误: {0}")]
    ConfigError(String),
    
    /// 验证错误
    #[error("验证错误: {0}")]
    Validation(String),
    
    /// IO 错误变体
    #[error("IO 错误: {0}")]
    IoError(String),
    
    /// 通用错误
    #[error("通用错误: {0}")]
    General(String),
    
    /// 账户未找到
    #[error("账户未找到: {0}")]
    AccountNotFound(String),
    
    /// 无效域名
    #[error("无效域名: {0}")]
    InvalidDomain(String),
    
    /// 订单失败
    #[error("订单失败: {0}")]
    OrderFailed(String),
    
    /// 挑战验证失败
    #[error("挑战验证失败: {0}")]
    ChallengeValidationFailed(String),
    
    /// 超时错误
    #[error("操作超时: {0}")]
    Timeout(String),
    
    /// 无效URL错误
    #[error("无效URL: {0}")]
    InvalidUrl(String),
    
    /// DNS错误变体
    #[error("DNS错误: {0}")]
    DnsError(String),
    
    /// 证书错误变体
    #[error("证书错误: {0}")]
    CertificateError(String),
}

/// 认证错误类型
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("无效令牌: {0}")]
    InvalidToken(String),
    
    #[error("API 权限不足")]
    InsufficientPermissions,
    
    #[error("缺少必需权限")]
    MissingPermissions,
    
    #[error("此账户未启用 ACME")]
    AcmeDisabled,
    
    #[error("服务错误: {0}")]
    ServiceError(String),
    
    #[error("无效的 API 响应")]
    InvalidResponse,
    
    #[error("超出速率限制")]
    RateLimitExceeded,
}

/// 证书错误类型
#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("无效的证书格式")]
    InvalidFormat,
    
    #[error("证书已过期")]
    Expired,
    
    #[error("未找到证书: {0}")]
    NotFound(String),
    
    #[error("证书解析错误: {0}")]
    ParseError(String),
    
    #[error("证书验证失败: {0}")]
    ValidationFailed(String),
    
    #[error("证书续期失败: {0}")]
    RenewalFailed(String),
}

/// DNS 错误类型
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS 记录创建失败: {0}")]
    RecordCreationFailed(String),
    
    #[error("DNS 记录删除失败: {0}")]
    RecordDeletionFailed(String),
    
    #[error("未找到 DNS 记录: {0}")]
    RecordNotFound(String),
    
    #[error("DNS 传播超时")]
    PropagationTimeout,
    
    #[error("无效的 DNS 提供商配置")]
    InvalidProviderConfig,
    
    #[error("DNS 提供商 API 错误: {0}")]
    ProviderApiError(String),
}

/// 加密错误类型
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("密钥生成失败: {0}")]
    KeyGenerationFailed(String),
    
    #[error("密钥解析失败: {0}")]
    KeyParsingFailed(String),
    
    #[error("无效的密钥格式")]
    InvalidKeyFormat,
    
    #[error("签名生成失败: {0}")]
    SignatureFailed(String),
    
    #[error("PEM 编码/解码失败: {0}")]
    PemError(String),
    
    #[error("不支持的算法: {0}")]
    UnsupportedAlgorithm(String),
}

/// 结果类型别名
pub type Result<T> = std::result::Result<T, AcmeError>;
pub type AcmeResult<T> = std::result::Result<T, AcmeError>;
pub type AuthResult<T> = std::result::Result<T, AuthError>;
pub type CertResult<T> = std::result::Result<T, CertificateError>;
pub type DnsResult<T> = std::result::Result<T, DnsError>;
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// 错误转换实现
impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        CryptoError::KeyGenerationFailed("Ring 加密操作失败".to_string())
    }
}

impl From<pem::PemError> for CryptoError {
    fn from(err: pem::PemError) -> Self {
        CryptoError::PemError(err.to_string())
    }
}

/// 便捷的错误创建宏
#[macro_export]
macro_rules! acme_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::AcmeError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::AcmeError::$variant(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! auth_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::AuthError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::AuthError::$variant(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! cert_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::CertificateError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::CertificateError::$variant(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! dns_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::DnsError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::DnsError::$variant(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! crypto_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::CryptoError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::CryptoError::$variant(format!($fmt, $($arg)*))
    };
}