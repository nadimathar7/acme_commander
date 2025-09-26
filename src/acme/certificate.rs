//! ACME 证书管理模块
//! 处理证书签名请求(CSR)生成、证书下载和管理

use crate::crypto::{KeyPair, PemData, PemType};
use crate::error::{AcmeError, AcmeResult};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration as StdDuration};
use ::time::OffsetDateTime;
use x509_parser::prelude::*;

/// 证书请求参数
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// 主域名
    pub common_name: String,
    /// 备用域名列表
    pub subject_alternative_names: Vec<String>,
    /// 组织名称
    pub organization: Option<String>,
    /// 组织单位
    pub organizational_unit: Option<String>,
    /// 国家代码
    pub country: Option<String>,
    /// 省份/州
    pub state_or_province: Option<String>,
    /// 城市
    pub locality: Option<String>,
    /// 邮箱地址
    pub email_address: Option<String>,
    /// 证书有效期（天数）
    pub validity_days: Option<u32>,
    /// 密钥用途
    pub key_usage: Vec<KeyUsage>,
    /// 扩展密钥用途
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
}

/// 密钥用途
#[derive(Debug, Clone, PartialEq)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

/// 扩展密钥用途
#[derive(Debug, Clone, PartialEq)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

/// 证书信息
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// 证书主题
    pub subject: String,
    /// 证书颁发者
    pub issuer: String,
    /// 序列号
    pub serial_number: String,
    /// 有效期开始时间
    pub not_before: SystemTime,
    /// 有效期结束时间
    pub not_after: SystemTime,
    /// 主题备用名称
    pub subject_alternative_names: Vec<String>,
    /// 指纹 (SHA-256)
    pub fingerprint_sha256: String,
    /// 密钥用途
    pub key_usage: Vec<String>,
    /// 扩展密钥用途
    pub extended_key_usage: Vec<String>,
    /// 是否为 CA 证书
    pub is_ca: bool,
}

/// 证书链信息
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// 叶子证书（终端实体证书）
    pub leaf_certificate: CertificateInfo,
    /// 中间证书列表
    pub intermediate_certificates: Vec<CertificateInfo>,
    /// 根证书（可选）
    pub root_certificate: Option<CertificateInfo>,
    /// 完整的 PEM 格式证书链
    pub full_chain_pem: String,
    /// 仅叶子证书的 PEM 格式
    pub certificate_pem: String,
}

/// 证书管理器
#[derive(Debug)]
pub struct CertificateManager {
    /// 证书密钥对
    certificate_key: KeyPair,
}

impl Default for CertificateRequest {
    fn default() -> Self {
        Self {
            common_name: String::new(),
            subject_alternative_names: Vec::new(),
            organization: None,
            organizational_unit: None,
            country: None,
            state_or_province: None,
            locality: None,
            email_address: None,
            validity_days: Some(90), // 默认 90 天
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
        }
    }
}

impl CertificateManager {
    /// 创建新的证书管理器
    pub fn new(certificate_key: KeyPair) -> Self {
        Self {
            certificate_key,
        }
    }
    
    /// 生成证书签名请求 (CSR)
    pub fn generate_csr(&self, request: &CertificateRequest) -> AcmeResult<Vec<u8>> {
        // 验证请求参数
        if request.common_name.is_empty() {
            return Err(AcmeError::InvalidDomain("通用名称不能为空".to_string()));
        }
        
        // 创建证书参数
        let mut params = CertificateParams::new(vec![request.common_name.clone()]);
        
        // 设置主题信息
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, &request.common_name);
        
        if let Some(org) = &request.organization {
            distinguished_name.push(DnType::OrganizationName, org);
        }
        
        if let Some(ou) = &request.organizational_unit {
            distinguished_name.push(DnType::OrganizationalUnitName, ou);
        }
        
        if let Some(country) = &request.country {
            distinguished_name.push(DnType::CountryName, country);
        }
        
        if let Some(state) = &request.state_or_province {
            distinguished_name.push(DnType::StateOrProvinceName, state);
        }
        
        if let Some(locality) = &request.locality {
            distinguished_name.push(DnType::LocalityName, locality);
        }
        
        params.distinguished_name = distinguished_name;
        
        // 添加备用域名
        for san in &request.subject_alternative_names {
            params.subject_alt_names.push(SanType::DnsName(san.clone()));
        }
        
        // CSR 中不设置密钥用途和扩展密钥用途，这些由 CA 决定
        // 移除这些设置以避免 rcgen 的 "Certificate parameter unsupported in CSR" 错误
        
        // CSR 不需要设置有效期，有效期由 CA 决定
        // 移除有效期设置以避免 rcgen 的 "Certificate parameter unsupported in CSR" 错误
        
        // 从密钥对获取私钥
        let private_key_der = self.certificate_key.private_key_der()
            .map_err(|e| AcmeError::CryptoError(format!("获取私钥DER失败: {}", e)))?;
        
        // 创建 rcgen 密钥对，明确指定 ECDSA P-384 算法
        let key_pair = rcgen::KeyPair::from_der_and_sign_algo(&private_key_der, &rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| AcmeError::CryptoError(format!("创建rcgen密钥对失败: {}", e)))?;
        
        params.key_pair = Some(key_pair);
        // 明确设置签名算法为 ECDSA P-384 SHA-384
        params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        
        // 生成证书（用于创建 CSR）
        let cert = Certificate::from_params(params)
            .map_err(|e| AcmeError::CertificateError(format!("创建证书失败: {}", e)))?;
        
        // 生成 CSR
        let csr_der = cert.serialize_request_der()
            .map_err(|e| AcmeError::CertificateError(format!("生成CSR失败: {}", e)))?;
        
        Ok(csr_der)
    }
    
    /// 生成 CSR 的 PEM 格式
    pub fn generate_csr_pem(&self, request: &CertificateRequest) -> AcmeResult<String> {
        let csr_der = self.generate_csr(request)?;
        let pem_data = PemData::new(PemType::CertificateRequest, csr_der)
            .map_err(|e| AcmeError::CryptoError(format!("创建PEM数据失败: {}", e)))?;
        Ok(pem_data.as_pem_string().to_string())
    }
    
    /// 解析证书链
    pub fn parse_certificate_chain(&self, certificate_pem: &str) -> AcmeResult<CertificateChain> {
        let pem_blocks = crate::crypto::pem::parse_multiple_pem(certificate_pem)
            .map_err(|e| AcmeError::CertificateError(format!("解析PEM失败: {}", e)))?;
        
        let mut certificates = Vec::new();
        
        for pem_block in pem_blocks {
            if pem_block.pem_type == PemType::Certificate {
                let cert_info = self.parse_certificate_der(&pem_block.data)?;
                certificates.push(cert_info);
            }
        }
        
        if certificates.is_empty() {
            return Err(AcmeError::CertificateError("PEM数据中未找到证书".to_string()));
        }
        
        // 第一个证书是叶子证书
        let leaf_certificate = certificates[0].clone();
        
        // 其余证书是中间证书
        let intermediate_certificates = certificates[1..].to_vec();
        
        // 查找根证书（通常是自签名的）
        let root_certificate = intermediate_certificates.iter()
            .find(|cert| cert.subject == cert.issuer)
            .cloned();
        
        // 提取仅叶子证书的 PEM
        let certificate_pem = self.extract_first_certificate_pem(certificate_pem)?;
        
        Ok(CertificateChain {
            leaf_certificate,
            intermediate_certificates,
            root_certificate,
            full_chain_pem: certificate_pem.to_string(),
            certificate_pem,
        })
    }
    
    /// 解析单个证书的 DER 格式
    fn parse_certificate_der(&self, cert_der: &[u8]) -> AcmeResult<CertificateInfo> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| AcmeError::CertificateError(format!("解析证书失败: {}", e)))?;
        
        // 提取基本信息
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let serial_number = format!("{:x}", cert.serial);
        
        // 转换时间
        let not_before = self.asn1_time_to_system_time(&cert.validity().not_before)?;
        let not_after = self.asn1_time_to_system_time(&cert.validity().not_after)?;
        
        // 提取 SAN
        let mut subject_alternative_names = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for san in &san_ext.value.general_names {
                if let GeneralName::DNSName(dns_name) = san {
                    subject_alternative_names.push(dns_name.to_string());
                }
            }
        }
        
        // 计算指纹
        let fingerprint_sha256 = self.calculate_certificate_fingerprint(cert_der)?;
        
        // 提取密钥用途
        let key_usage = self.extract_key_usage(&cert)?;
        let extended_key_usage = self.extract_extended_key_usage(&cert)?;
        
        // 检查是否为 CA 证书
        let is_ca = cert.basic_constraints()
            .map(|bc| bc.map(|bc| bc.value.ca).unwrap_or(false))
            .unwrap_or(false);
        
        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            subject_alternative_names,
            fingerprint_sha256,
            key_usage,
            extended_key_usage,
            is_ca,
        })
    }
    
    /// 转换 ASN.1 时间为 SystemTime
    fn asn1_time_to_system_time(&self, asn1_time: &ASN1Time) -> AcmeResult<SystemTime> {
        let timestamp = asn1_time.timestamp();
        Ok(UNIX_EPOCH + StdDuration::from_secs(timestamp as u64))
    }
    
    /// 计算证书指纹
    fn calculate_certificate_fingerprint(&self, cert_der: &[u8]) -> AcmeResult<String> {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();
        
        Ok(hex::encode(hash))
    }
    
    /// 提取密钥用途
    fn extract_key_usage(&self, cert: &X509Certificate) -> AcmeResult<Vec<String>> {
        let mut usage = Vec::new();
        
        if let Ok(Some(ku)) = cert.key_usage() {
            let key_usage = &ku.value;
            if key_usage.digital_signature() {
                usage.push("数字签名".to_string());
            }
            if key_usage.key_encipherment() {
                usage.push("密钥加密".to_string());
            }
            if key_usage.key_agreement() {
                usage.push("密钥协商".to_string());
            }
            if key_usage.key_cert_sign() {
                usage.push("证书签名".to_string());
            }
            if key_usage.crl_sign() {
                usage.push("CRL签名".to_string());
            }
        }
        
        Ok(usage)
    }
    
    /// 提取扩展密钥用途
    fn extract_extended_key_usage(&self, cert: &X509Certificate) -> AcmeResult<Vec<String>> {
        let mut usage = Vec::new();
        
        if let Ok(Some(eku)) = cert.extended_key_usage() {
            for oid in &eku.value.other {
                match oid.to_string().as_str() {
                    "1.3.6.1.5.5.7.3.1" => usage.push("服务器认证".to_string()),
                    "1.3.6.1.5.5.7.3.2" => usage.push("客户端认证".to_string()),
                    "1.3.6.1.5.5.7.3.3" => usage.push("代码签名".to_string()),
                    "1.3.6.1.5.5.7.3.4" => usage.push("邮件保护".to_string()),
                    "1.3.6.1.5.5.7.3.8" => usage.push("时间戳".to_string()),
                    "1.3.6.1.5.5.7.3.9" => usage.push("OCSP签名".to_string()),
                    _ => usage.push(format!("未知 ({})", oid)),
                }
            }
        }
        
        Ok(usage)
    }
    
    /// 提取第一个证书的 PEM
    fn extract_first_certificate_pem(&self, full_pem: &str) -> AcmeResult<String> {
        let lines: Vec<&str> = full_pem.lines().collect();
        let mut cert_lines = Vec::new();
        let mut in_cert = false;
        
        for line in lines {
            if line.starts_with("-----BEGIN CERTIFICATE-----") {
                in_cert = true;
                cert_lines.push(line);
            } else if line.starts_with("-----END CERTIFICATE-----") {
                cert_lines.push(line);
                break; // 只取第一个证书
            } else if in_cert {
                cert_lines.push(line);
            }
        }
        
        if cert_lines.is_empty() {
            return Err(AcmeError::CertificateError("PEM数据中未找到证书".to_string()));
        }
        
        Ok(cert_lines.join("\n"))
    }
    
    /// 提取仅包含中间证书的证书链PEM（不包含叶子证书）
    pub fn extract_intermediate_chain_pem(&self, full_pem: &str) -> AcmeResult<String> {
        let lines: Vec<&str> = full_pem.lines().collect();
        let mut chain_lines = Vec::new();
        let mut cert_count = 0;
        let mut in_cert = false;
        let mut current_cert_lines = Vec::new();
        
        for line in lines {
            if line.starts_with("-----BEGIN CERTIFICATE-----") {
                in_cert = true;
                current_cert_lines.clear();
                current_cert_lines.push(line);
            } else if line.starts_with("-----END CERTIFICATE-----") {
                current_cert_lines.push(line);
                in_cert = false;
                
                // 跳过第一个证书（叶子证书），保留后续的中间证书
                if cert_count > 0 {
                    if !chain_lines.is_empty() {
                        chain_lines.push(""); // 添加空行分隔证书
                    }
                    chain_lines.extend(current_cert_lines.clone());
                }
                
                cert_count += 1;
            } else if in_cert {
                current_cert_lines.push(line);
            }
        }
        
        // 如果没有中间证书，返回空字符串
        if chain_lines.is_empty() {
            return Ok(String::new());
        }
        
        Ok(chain_lines.join("\n"))
    }
    
    /// 转换密钥用途
    fn convert_key_usage(&self, usage: &[KeyUsage]) -> Vec<rcgen::KeyUsagePurpose> {
        usage.iter().filter_map(|ku| {
            match ku {
                KeyUsage::DigitalSignature => Some(rcgen::KeyUsagePurpose::DigitalSignature),
                KeyUsage::KeyEncipherment => Some(rcgen::KeyUsagePurpose::KeyEncipherment),
                KeyUsage::KeyAgreement => Some(rcgen::KeyUsagePurpose::KeyAgreement),
                KeyUsage::KeyCertSign => Some(rcgen::KeyUsagePurpose::KeyCertSign),
                KeyUsage::CrlSign => Some(rcgen::KeyUsagePurpose::CrlSign),
                _ => None, // rcgen 不支持所有用途
            }
        }).collect()
    }
    
    /// 转换扩展密钥用途
    fn convert_extended_key_usage(&self, usage: &[ExtendedKeyUsage]) -> Vec<rcgen::ExtendedKeyUsagePurpose> {
        usage.iter().filter_map(|eku| {
            match eku {
                ExtendedKeyUsage::ServerAuth => Some(rcgen::ExtendedKeyUsagePurpose::ServerAuth),
                ExtendedKeyUsage::ClientAuth => Some(rcgen::ExtendedKeyUsagePurpose::ClientAuth),
                ExtendedKeyUsage::CodeSigning => Some(rcgen::ExtendedKeyUsagePurpose::CodeSigning),
                ExtendedKeyUsage::EmailProtection => Some(rcgen::ExtendedKeyUsagePurpose::EmailProtection),
                ExtendedKeyUsage::TimeStamping => Some(rcgen::ExtendedKeyUsagePurpose::TimeStamping),
                ExtendedKeyUsage::OcspSigning => Some(rcgen::ExtendedKeyUsagePurpose::OcspSigning),
            }
        }).collect()
    }
    
    /// 验证证书链
    pub fn validate_certificate_chain(&self, chain: &CertificateChain) -> AcmeResult<bool> {
        // 基本验证：检查证书是否在有效期内
        let now = SystemTime::now();
        
        if now < chain.leaf_certificate.not_before || now > chain.leaf_certificate.not_after {
            return Ok(false);
        }
        
        // 检查中间证书的有效期
        for intermediate in &chain.intermediate_certificates {
            if now < intermediate.not_before || now > intermediate.not_after {
                return Ok(false);
            }
        }
        
        // 检查根证书的有效期（如果存在）
        if let Some(root) = &chain.root_certificate {
            if now < root.not_before || now > root.not_after {
                return Ok(false);
            }
        }
        
        // 更多验证逻辑可以在这里添加
        // 例如：签名验证、证书链完整性检查等
        
        Ok(true)
    }
    
    /// 获取证书密钥
    pub fn certificate_key(&self) -> &KeyPair {
        &self.certificate_key
    }
}

/// 便捷函数：创建简单的域名证书请求
pub fn create_domain_certificate_request(
    common_name: String,
    subject_alternative_names: Vec<String>,
) -> CertificateRequest {
    CertificateRequest {
        common_name,
        subject_alternative_names,
        ..Default::default()
    }
}

/// 便捷函数：生成域名 CSR
pub fn generate_domain_csr(
    certificate_key: &KeyPair,
    domains: &[String],
) -> AcmeResult<Vec<u8>> {
    if domains.is_empty() {
        return Err(AcmeError::InvalidDomain("至少需要一个域名".to_string()));
    }
    
    let common_name = domains[0].clone();
    let sans = domains[1..].to_vec();
    
    let request = create_domain_certificate_request(common_name, sans);
    let manager = CertificateManager::new(certificate_key.clone());
    
    manager.generate_csr(&request)
}