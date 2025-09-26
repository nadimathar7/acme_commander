//! 配置管理模块
//! 处理 ACME Commander 的配置文件、环境变量和命令行参数

use crate::error::{AcmeError, AcmeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;

/// ACME Commander 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// ACME 服务器配置
    pub acme: AcmeServerConfig,
    /// 账户配置
    pub account: AccountConfig,
    /// 证书配置
    pub certificate: CertificateConfig,
    /// DNS 配置
    pub dns: DnsConfig,
    /// ZeroSSL 配置 (可选)
    pub zerossl: Option<ZeroSslConfig>,
    /// 日志配置
    pub logging: LoggingConfig,
    /// 安全配置 (可选)
    pub security: Option<SecurityConfig>,
    /// 高级配置 (可选)
    pub advanced: Option<AdvancedConfig>,
}

/// ACME 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeServerConfig {
    /// ACME 目录 URL
    pub directory_url: String,
    /// 服务器名称
    pub server_name: String,
    /// 是否为生产环境
    pub production: bool,
    /// 外部账户绑定 (EAB) 配置
    pub eab: Option<EabConfig>,
    /// 请求超时时间（秒）
    pub timeout_seconds: u64,
    /// 重试次数
    pub retry_count: u32,
    /// 重试间隔（秒）
    pub retry_interval: u64,
}

/// 外部账户绑定配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EabConfig {
    /// EAB Key ID
    pub key_id: String,
    /// EAB HMAC Key (base64 编码)
    pub hmac_key: String,
}

/// 账户配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    /// 账户邮箱
    pub email: String,
    /// 账户密钥文件路径
    pub key_file: PathBuf,
    /// 是否同意服务条款
    pub terms_of_service_agreed: bool,
    /// 账户 URL（可选，用于已注册账户）
    pub account_url: Option<String>,
    /// 联系信息
    pub contacts: Vec<String>,
}

/// 证书配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// 证书密钥文件路径
    pub key_file: PathBuf,
    /// 证书文件路径
    pub cert_file: PathBuf,
    /// 证书链文件路径
    pub chain_file: PathBuf,
    /// 完整链文件路径
    pub fullchain_file: PathBuf,
    /// CSR文件路径（可选，如果不存在则自动生成）
    pub csr_file: Option<PathBuf>,
    /// 域名列表
    pub domains: Vec<String>,
            /// 组织信息
    pub organization: Option<String>,
    /// 组织单位
    pub organizational_unit: Option<String>,
    /// 国家代码
    pub country: Option<String>,
    /// 省份/州
    pub state_or_province: Option<String>,
    /// 城市
    pub locality: Option<String>,
}

/// DNS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS 提供商
    pub provider: String,
    /// Cloudflare 配置
    pub cloudflare: Option<CloudflareConfig>,

    /// 传播等待时间（秒）
    pub propagation_timeout: u64,
    /// 传播检查间隔（秒）
    pub propagation_interval: u64,
    /// DNS 服务器列表（用于传播检查）
    pub dns_servers: Vec<String>,
    /// 默认 TTL
    pub default_ttl: u32,
}

/// Cloudflare DNS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    /// API Token
    pub api_token: Option<String>,
    /// API 基础 URL
    pub api_base_url: String,
    /// 请求超时时间（秒）
    pub timeout_seconds: u64,
}

/// ZeroSSL 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroSslConfig {
    /// API Key
    pub api_key: String,
    /// API 基础 URL
    pub api_base_url: String,
    /// 请求超时时间（秒）
    pub timeout_seconds: u64,
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// 日志级别
    pub level: String,
    /// 日志输出目标
    pub outputs: Vec<LogOutputConfig>,
    /// 是否启用彩色输出
    pub colored: bool,
    /// 时间戳格式
    pub timestamp_format: String,
}

/// 日志输出配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogOutputConfig {
    /// 输出类型（console, file, udp）
    pub output_type: String,
    /// 文件路径（用于 file 输出）
    pub file_path: Option<PathBuf>,
    /// UDP 地址（用于 udp 输出）
    pub udp_address: Option<String>,
    /// 日志级别过滤
    pub level_filter: Option<String>,
}

/// 安全配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 文件权限（八进制）
    pub file_permissions: u32,
    /// 密钥文件权限（八进制）
    pub key_file_permissions: u32,
    /// 是否验证证书链
    pub verify_certificate_chain: bool,
    /// 是否启用 OCSP 检查
    pub enable_ocsp_check: bool,
    /// 允许的密钥用途
    pub allowed_key_usages: Vec<String>,
    /// 允许的扩展密钥用途
    pub allowed_extended_key_usages: Vec<String>,
}

/// 高级配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// 并发限制
    pub concurrency_limit: u32,
    /// HTTP 用户代理
    pub user_agent: String,
    /// 是否启用 HTTP/2
    pub enable_http2: bool,
    /// 连接池大小
    pub connection_pool_size: u32,
    /// 连接超时时间（秒）
    pub connection_timeout: u64,
    /// 读取超时时间（秒）
    pub read_timeout: u64,
    /// 写入超时时间（秒）
    pub write_timeout: u64,
    /// 自定义 HTTP 头
    pub custom_headers: HashMap<String, String>,
    /// 代理配置
    pub proxy: Option<ProxyConfig>,
}

/// 代理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// 代理 URL
    pub url: String,
    /// 用户名
    pub username: Option<String>,
    /// 密码
    pub password: Option<String>,
}

/// 配置管理器
#[derive(Debug)]
pub struct ConfigManager {
    /// 配置文件路径
    config_file: PathBuf,
    /// 当前配置
    config: AcmeConfig,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            acme: AcmeServerConfig::default(),
            account: AccountConfig::default(),
            certificate: CertificateConfig::default(),
            dns: DnsConfig::default(),
            zerossl: None,
            logging: LoggingConfig::default(),
            security: None,
            advanced: None,
        }
    }
}

impl Default for AcmeServerConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            server_name: "Let's Encrypt Staging".to_string(),
            production: false,
            eab: None,
            timeout_seconds: 30,
            retry_count: 3,
            retry_interval: 5,
        }
    }
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            email: String::new(),
            key_file: PathBuf::from("account.key"),
            terms_of_service_agreed: false,
            account_url: None,
            contacts: Vec::new(),
        }
    }
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            key_file: PathBuf::from("cert.key"),
            cert_file: PathBuf::from("cert.pem"),
            chain_file: PathBuf::from("chain.pem"),
            fullchain_file: PathBuf::from("fullchain.pem"),
            csr_file: None,
            domains: Vec::new(),
            organization: None,
            organizational_unit: None,
            country: None,
            state_or_province: None,
            locality: None,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            provider: "cloudflare".to_string(),
            cloudflare: Some(CloudflareConfig::default()),
            propagation_timeout: 300,
            propagation_interval: 10,
            dns_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "208.67.222.222".to_string(),
                "9.9.9.9".to_string(),
            ],
            default_ttl: 60,
        }
    }
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            api_token: None,
            api_base_url: "https://api.cloudflare.com/client/v4".to_string(),
            timeout_seconds: 30,
        }
    }
}

impl Default for ZeroSslConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            api_base_url: "https://api.zerossl.com".to_string(),
            timeout_seconds: 30,
        }
    }
}



impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            outputs: vec![LogOutputConfig {
                output_type: "console".to_string(),
                file_path: None,
                udp_address: None,
                level_filter: None,
            }],
            colored: true,
            timestamp_format: "%Y-%m-%d %H:%M:%S".to_string(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            file_permissions: 0o644,
            key_file_permissions: 0o600,
            verify_certificate_chain: true,
            enable_ocsp_check: false,
            allowed_key_usages: vec![
                "Digital Signature".to_string(),
                "Key Encipherment".to_string(),
            ],
            allowed_extended_key_usages: vec![
                "Server Authentication".to_string(),
            ],
        }
    }
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            concurrency_limit: 10,
            user_agent: format!("acme-commander/{}", env!("CARGO_PKG_VERSION")),
            enable_http2: true,
            connection_pool_size: 10,
            connection_timeout: 30,
            read_timeout: 30,
            write_timeout: 30,
            custom_headers: HashMap::new(),
            proxy: None,
        }
    }
}

impl ConfigManager {
    /// 创建新的配置管理器
    pub fn new(config_file: PathBuf) -> Self {
        Self {
            config_file,
            config: AcmeConfig::default(),
        }
    }
    
    /// 从文件加载配置
    pub fn load_from_file(&mut self) -> AcmeResult<()> {
        if !self.config_file.exists() {
            return Err(AcmeError::ConfigError(format!(
                "Configuration file not found: {}",
                self.config_file.display()
            )));
        }
        
        let content = fs::read_to_string(&self.config_file)
            .map_err(|e| AcmeError::ConfigError(format!(
                "Failed to read configuration file: {}",
                e
            )))?;
        
        self.config = self.parse_config(&content)?;
        self.validate_config()?;
        
        Ok(())
    }
    
    /// 保存配置到文件
    pub fn save_to_file(&self) -> AcmeResult<()> {
        let content = self.serialize_config()?;
        
        // 确保目录存在
        if let Some(parent) = self.config_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AcmeError::ConfigError(format!(
                    "Failed to create config directory: {}",
                    e
                )))?;
        }
        
        fs::write(&self.config_file, content)
            .map_err(|e| AcmeError::ConfigError(format!(
                "Failed to write configuration file: {}",
                e
            )))?;
        
        Ok(())
    }
    
    /// 解析配置内容
    fn parse_config(&self, content: &str) -> AcmeResult<AcmeConfig> {
        // 根据文件扩展名选择解析器
        let extension = self.config_file
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("toml");
        
        match extension {
            "toml" => {
                toml::from_str(content)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to parse TOML config: {}", e)))
            }
            "yaml" | "yml" => {
                serde_yaml::from_str(content)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to parse YAML config: {}", e)))
            }
            "json" => {
                serde_json::from_str(content)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to parse JSON config: {}", e)))
            }
            _ => Err(AcmeError::ConfigError(format!(
                "Unsupported configuration file format: {}",
                extension
            ))),
        }
    }
    
    /// 序列化配置
    fn serialize_config(&self) -> AcmeResult<String> {
        let extension = self.config_file
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("toml");
        
        match extension {
            "toml" => {
                toml::to_string_pretty(&self.config)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to serialize TOML config: {}", e)))
            }
            "yaml" | "yml" => {
                serde_yaml::to_string(&self.config)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to serialize YAML config: {}", e)))
            }
            "json" => {
                serde_json::to_string_pretty(&self.config)
                    .map_err(|e| AcmeError::ConfigError(format!("Failed to serialize JSON config: {}", e)))
            }
            _ => Err(AcmeError::ConfigError(format!(
                "Unsupported configuration file format: {}",
                extension
            ))),
        }
    }
    
    /// 验证配置
    fn validate_config(&self) -> AcmeResult<()> {
        // 验证 ACME 服务器配置
        if self.config.acme.directory_url.is_empty() {
            return Err(AcmeError::ConfigError("ACME directory URL cannot be empty".to_string()));
        }
        
        // 验证账户配置
        if self.config.account.email.is_empty() {
            return Err(AcmeError::ConfigError("Account email cannot be empty".to_string()));
        }
        
        // 验证证书配置
        if self.config.certificate.domains.is_empty() {
            return Err(AcmeError::ConfigError("At least one domain must be specified".to_string()));
        }
        
                
        // 验证 DNS 提供商
        match self.config.dns.provider.as_str() {
            "cloudflare" => {
                if self.config.dns.cloudflare.is_none() {
                    return Err(AcmeError::ConfigError("Cloudflare configuration is required".to_string()));
                }
            }
            _ => {
                return Err(AcmeError::ConfigError(format!(
                    "Unsupported DNS provider: {}",
                    self.config.dns.provider
                )));
            }
        }
        
        Ok(())
    }
    
    /// 从环境变量加载配置
    pub fn load_from_env(&mut self) -> AcmeResult<()> {
        // 加载 ACME 服务器配置
        if let Ok(directory_url) = std::env::var("ACME_DIRECTORY_URL") {
            self.config.acme.directory_url = directory_url;
        }
        
        if let Ok(production) = std::env::var("ACME_PRODUCTION") {
            self.config.acme.production = production.parse().unwrap_or(false);
        }
        
        // 加载账户配置
        if let Ok(email) = std::env::var("ACME_EMAIL") {
            self.config.account.email = email;
        }
        
        if let Ok(terms_agreed) = std::env::var("ACME_TERMS_AGREED") {
            self.config.account.terms_of_service_agreed = terms_agreed.parse().unwrap_or(false);
        }
        
        // 加载 DNS 配置
        if let Ok(provider) = std::env::var("DNS_PROVIDER") {
            self.config.dns.provider = provider;
        }
        
        // 加载 Cloudflare 配置
        if let Ok(api_token) = std::env::var("CLOUDFLARE_API_TOKEN") {
            if let Some(ref mut cloudflare) = self.config.dns.cloudflare {
                cloudflare.api_token = Some(api_token);
            }
        }

        // 加载 ZeroSSL 配置
        if let Ok(api_key) = std::env::var("ZEROSSL_API_KEY") {
            if self.config.zerossl.is_none() {
                self.config.zerossl = Some(ZeroSslConfig::default());
            }
            if let Some(ref mut zerossl) = self.config.zerossl {
                zerossl.api_key = api_key;
            }
        }
        
        // 加载日志配置
        if let Ok(log_level) = std::env::var("LOG_LEVEL") {
            self.config.logging.level = log_level;
        }
        
        Ok(())
    }
    
    /// 合并命令行参数
    pub fn merge_cli_args(&mut self, args: &CliArgs) -> AcmeResult<()> {
        // 合并域名
        if !args.domains.is_empty() {
            self.config.certificate.domains = args.domains.clone();
        }
        
        // 合并邮箱
        if let Some(ref email) = args.email {
            self.config.account.email = email.clone();
        }
        
        // 合并服务器
        if let Some(ref server) = args.server {
            match server.as_str() {
                "letsencrypt" | "production" => {
                    self.config.acme.directory_url = "https://acme-v02.api.letsencrypt.org/directory".to_string();
                    self.config.acme.server_name = "Let's Encrypt Production".to_string();
                    self.config.acme.production = true;
                }
                "letsencrypt-staging" | "staging" => {
                    self.config.acme.directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
                    self.config.acme.server_name = "Let's Encrypt Staging".to_string();
                    self.config.acme.production = false;
                }
                url if url.starts_with("http") => {
                    self.config.acme.directory_url = url.to_string();
                    self.config.acme.server_name = "Custom Server".to_string();
                }
                _ => {
                    return Err(AcmeError::ConfigError(format!("Invalid server: {}", server)));
                }
            }
        }
        
        // 合并 DNS 提供商
        if let Some(ref provider) = args.dns_provider {
            self.config.dns.provider = provider.clone();
        }
        
        // 合并文件路径
        if let Some(ref key_file) = args.key_file {
            self.config.certificate.key_file = key_file.clone();
        }
        
        if let Some(ref cert_file) = args.cert_file {
            self.config.certificate.cert_file = cert_file.clone();
        }
        
        if let Some(ref chain_file) = args.chain_file {
            self.config.certificate.chain_file = chain_file.clone();
        }
        
        if let Some(ref fullchain_file) = args.fullchain_file {
            self.config.certificate.fullchain_file = fullchain_file.clone();
        }
        
        // 合并其他选项
        if args.agree_tos {
            self.config.account.terms_of_service_agreed = true;
        }
        
        Ok(())
    }
    
    /// 获取配置
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }
    
    /// 获取可变配置
    pub fn config_mut(&mut self) -> &mut AcmeConfig {
        &mut self.config
    }
    
    /// 设置配置
    pub fn set_config(&mut self, config: AcmeConfig) {
        self.config = config;
    }
    
    /// 获取配置文件路径
    pub fn config_file(&self) -> &Path {
        &self.config_file
    }
}

/// 命令行参数（用于配置合并）
#[derive(Debug, Clone, Default)]
pub struct CliArgs {
    pub domains: Vec<String>,
    pub email: Option<String>,
    pub server: Option<String>,
    pub dns_provider: Option<String>,
    pub key_file: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub chain_file: Option<PathBuf>,
    pub fullchain_file: Option<PathBuf>,
    pub agree_tos: bool,
}

/// 便捷函数：创建默认配置文件路径
pub fn default_config_file() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("acme-commander")
        .join("config.toml")
}

/// 便捷函数：创建配置管理器
pub fn create_config_manager(config_file: Option<PathBuf>) -> ConfigManager {
    let config_file = config_file.unwrap_or_else(default_config_file);
    ConfigManager::new(config_file)
}

/// 便捷函数：加载配置
pub fn load_config(
    config_file: Option<PathBuf>,
    cli_args: Option<&CliArgs>,
) -> AcmeResult<AcmeConfig> {
    let mut manager = create_config_manager(config_file);

    // 尝试从文件加载配置
    if manager.config_file().exists() {
        manager.load_from_file()?;
    }

    // 从环境变量加载配置
    manager.load_from_env()?;

    // 合并命令行参数
    if let Some(args) = cli_args {
        manager.merge_cli_args(args)?;
    }

    Ok(manager.config().clone())
}

/// 获取 Cloudflare API Token
/// 优先从配置文件读取，然后从环境变量读取
pub fn get_cloudflare_token(config_file: Option<PathBuf>) -> Option<String> {
    // 尝试从配置文件读取
    if let Ok(config) = load_config(config_file, None) {
        if let Some(token) = config.dns.cloudflare.as_ref().and_then(|c| c.api_token.as_ref()) {
            if !token.is_empty() {
                return Some(token.clone());
            }
        }
    }

    // 如果配置文件中没有，尝试从环境变量读取
    std::env::var("CLOUDFLARE_API_TOKEN").ok().filter(|token| !token.is_empty())
}

/// 获取 ZeroSSL API Key
/// 优先从配置文件读取，然后从环境变量读取
pub fn get_zerossl_api_key(config_file: Option<PathBuf>) -> Option<String> {
    // 尝试从配置文件读取
    if let Ok(config) = load_config(config_file, None) {
        if let Some(zerossl_config) = &config.zerossl {
            if !zerossl_config.api_key.is_empty() {
                return Some(zerossl_config.api_key.clone());
            }
        }
    }

    // 如果配置文件中没有，尝试从环境变量读取
    std::env::var("ZEROSSL_API_KEY").ok().filter(|key| !key.is_empty())
}