//! acme_commander 库的 DNS 验证自动测试
//! 使用 gs1.sukiyaki.su 域名在沙盒模式下运行，不使用 dry-run

use acme_commander::dns::cloudflare::CloudflareDnsManager;
use acme_commander::dns::{DnsManager, DnsChallengeManager};
use acme_commander::acme::{AcmeClient, AcmeConfig, ChallengeType, OrderStatus};
use acme_commander::crypto::KeyPair;
use acme_commander::directories;
use acme_commander::logger::{init_logger_silent_with_config, LogConfig, LogLevel, LogOutput};
use acme_commander::error::AcmeResult;

/// 测试域名
const TEST_DOMAIN: &str = "gs1.sukiyaki.su";


/// 主测试函数
#[tokio::test]
async fn test_gs1_sukiyaki_dns_validation() -> AcmeResult<()> {
    // 初始化日志（安全模式，避免重复初始化错误）
    init_logger_silent_with_config(LogConfig {
        level: LogLevel::Debug,
        output: LogOutput::Terminal,
        ..Default::default()
    }).expect("初始化日志失败");
    
    println!("=== 开始 gs1.sukiyaki.su DNS 验证测试 ===");
    println!("测试模式: 沙盒模式 (Let's Encrypt 测试环境)");
    println!("Dry-run: 否 (真实沙盒环境测试)");
    
    // 第一步：验证 Cloudflare DNS 管理器
    println!("\n[步骤 1] 验证 Cloudflare DNS 管理器");
    let dns_manager = test_cloudflare_dns_manager().await?;
    
    // 第二步：创建 DNS 挑战管理器
    println!("\n[步骤 2] 创建 DNS 挑战管理器");
    let dns_challenge_manager = DnsChallengeManager::new(
        Box::new(dns_manager),
        Some(60),  // TTL 60 秒
        Some(300), // 传播超时 5 分钟
    );
    
    // 第三步：创建 ACME 客户端
    println!("\n[步骤 3] 创建 ACME 客户端");
    let (mut acme_client, account_key) = create_acme_client().await?;
    
    // 第四步：创建证书密钥
    println!("\n[步骤 4] 创建证书密钥");
    let certificate_key = KeyPair::generate()?;
    println!("✅ 成功生成证书密钥");
    
    // 第五步：创建新订单
    println!("\n[步骤 5] 创建新订单");
    let (order, order_url) = {
        let mut order_manager = acme_commander::acme::order::OrderManager::new(&mut acme_client);
        order_manager.create_order(&[TEST_DOMAIN.to_string()], None, None).await?
    };
    println!("✅ 成功创建订单，状态: {:?}", order.status);
    
    // 第六步：获取授权
    println!("\n[步骤 6] 获取授权");
    let authorizations = {
        let mut order_manager = acme_commander::acme::order::OrderManager::new(&mut acme_client);
        order_manager.get_order_authorizations(&order).await?
    };
    println!("✅ 成功获取授权，数量: {}", authorizations.len());
    
    // 第七步：处理 DNS 挑战
    println!("\n[步骤 7] 处理 DNS 挑战");
    for auth in &authorizations {
        println!("处理域名 {} 的授权", auth.identifier.value);
        
        // 查找 DNS-01 挑战
        let dns_challenge = auth.challenges.iter()
            .find(|c| c.challenge_type == ChallengeType::Dns01)
            .ok_or_else(|| acme_commander::error::AcmeError::ProtocolError(
                "未找到 DNS-01 挑战".to_string()
            ))?;
        
        println!("✅ 找到 DNS-01 挑战");
        
        // 准备挑战信息
        let challenge_info = {
            let mut challenge_manager = acme_commander::acme::challenge::ChallengeManager::new(&mut acme_client);
            challenge_manager.prepare_challenge(dns_challenge)?
        };
        
        // 获取 DNS 记录值
        let dns_value = if let acme_commander::acme::challenge::ChallengeInfo::Dns01(dns01) = challenge_info {
            println!("✅ 成功获取 DNS-01 值: {}", dns01.record_value);
            dns01.record_value
        } else {
            return Err(acme_commander::error::AcmeError::ProtocolError(
                "挑战类型不匹配".to_string()
            ));
        };
        
        // 添加 DNS 记录
        let challenge_record = dns_challenge_manager.add_challenge_record(
            &auth.identifier.value,
            &dns_value,
            false, // 关闭 dry-run 模式，使用真实的沙盒环境
        ).await?;
        
        println!("✅ 成功添加 DNS 记录: {}", challenge_record.record_name);
        
        // 等待 DNS 传播
        let propagation_result = dns_challenge_manager.wait_for_propagation(
            &challenge_record,
            false, // 关闭 dry-run 模式，使用真实的沙盒环境
        ).await?;
        
        println!("✅ DNS 传播结果: 已传播 = {}", propagation_result.propagated);
        println!("   成功的服务器: {:?}", propagation_result.successful_servers);
        
        // 在dry-run模式下跳过ACME服务器验证
        if acme_client.is_dry_run() {
            println!("🧪 [演练模式] 跳过ACME服务器挑战验证");
            println!("✅ [演练模式] 挑战验证将会成功");
        } else {
            // 通知 ACME 服务器验证挑战
            let challenge_result = {
                let mut challenge_manager = acme_commander::acme::challenge::ChallengeManager::new(&mut acme_client);
                let result = challenge_manager.respond_to_challenge(&dns_challenge).await?;
                
                // 等待挑战完成
                challenge_manager.wait_for_challenge_completion(
                    &dns_challenge.url,
                    10, // 最大尝试次数
                    std::time::Duration::from_secs(5) // 等待间隔
                ).await?
            };
            println!("✅ 挑战验证结果: {:?}", challenge_result.status);
        }
    }
    
    // 第八步：轮询订单状态
    println!("\n[步骤 8] 轮询订单状态");
    let updated_order = if acme_client.is_dry_run() {
        println!("🧪 [演练模式] 跳过订单状态轮询");
        println!("✅ [演练模式] 订单状态将变为Ready");
        // 在dry-run模式下，我们模拟一个Ready状态的订单
        acme_commander::acme::Order {
            status: OrderStatus::Ready,
            expires: order.expires,
            identifiers: order.identifiers,
            authorizations: order.authorizations,
            finalize: order.finalize,
            certificate: None,
            error: None,
        }
    } else {
        let mut order_manager = acme_commander::acme::order::OrderManager::new(&mut acme_client);
        order_manager.wait_for_order_ready(&order_url, 10, std::time::Duration::from_secs(5)).await?
    };
    println!("✅ 更新后的订单状态: {:?}", updated_order.status);
    
    // 第九步：完成证书签发 (如果订单已就绪)
    if updated_order.status == OrderStatus::Ready {
        println!("\n[步骤 9] 完成证书签发");
        
        if acme_client.is_dry_run() {
            println!("🧪 [演练模式] 跳过证书签发流程");
            println!("✅ [演练模式] 证书将被成功签发");
            println!("✅ [演练模式] 证书将可供下载");
        } else {
            // 创建证书管理器
            let cert_manager = acme_commander::acme::certificate::CertificateManager::new(certificate_key.clone());
            
            // 创建证书请求
            let cert_request = acme_commander::acme::certificate::create_domain_certificate_request(
                TEST_DOMAIN.to_string(),
                vec![],
            );
            
            // 生成 CSR
            let csr_der = cert_manager.generate_csr(&cert_request)?;
            println!("✅ 成功生成 CSR");
            
            // 完成订单
            let finalized_order = {
                let mut order_manager = acme_commander::acme::order::OrderManager::new(&mut acme_client);
                order_manager.finalize_order(&updated_order, &csr_der).await?
            };
            println!("✅ 最终订单状态: {:?}", finalized_order.status);
            
            // 下载证书
            if finalized_order.status == OrderStatus::Valid {
                if let Some(cert_url) = &finalized_order.certificate {
                    let certificate = {
                        let mut order_manager = acme_commander::acme::order::OrderManager::new(&mut acme_client);
                        order_manager.download_certificate(cert_url).await?
                    };
                    println!("✅ 证书已下载，长度: {}", certificate.len());
                    
                    // 可以将证书保存到文件
                    // std::fs::write("certificate.pem", certificate).expect("保存证书失败");
                } else {
                    println!("⚠️ 订单有效但未提供证书URL");
                }
            }
        }
    }
    
    // 第十步：清理 DNS 记录
    println!("\n[步骤 10] 清理 DNS 记录");
    for auth in &authorizations {
        cleanup_dns_records(&dns_challenge_manager, auth).await?;
    }
    
    println!("\n=== gs1.sukiyaki.su DNS 验证测试完成 ===");
    Ok(())
}

/// 测试 Cloudflare DNS 管理器
async fn test_cloudflare_dns_manager() -> AcmeResult<CloudflareDnsManager> {
    // 创建 Cloudflare DNS 管理器
    let token = acme_commander::config::get_cloudflare_token(None)
        .ok_or_else(|| acme_commander::error::AcmeError::ConfigError(
            "未配置 Cloudflare API Token。请在 config.toml 中配置 [cloudflare] api_token 或设置 CLOUDFLARE_API_TOKEN 环境变量".to_string()
        ))?;
    let dns_manager = CloudflareDnsManager::new(token)?;
    println!("✅ 成功创建 Cloudflare DNS 管理器");
    
    // 验证 Cloudflare 凭证
    let is_valid = dns_manager.validate_credentials().await?;
    if is_valid {
        println!("✅ Cloudflare API Token 验证成功");
    } else {
        println!("❌ Cloudflare API Token 无效");
        panic!("Cloudflare API Token 无效，请提供有效的 Token");
    }
    
    Ok(dns_manager)
}

/// 创建 ACME 客户端
async fn create_acme_client() -> AcmeResult<(AcmeClient, KeyPair)> {
    // 创建账户密钥
    let account_key = KeyPair::generate()?;
    println!("✅ 成功生成账户密钥");
    
    // 创建 ACME 客户端配置 (使用 Let's Encrypt 测试环境进行真实沙盒测试)
    let acme_config = AcmeConfig {
        directory_url: directories::LETSENCRYPT_STAGING.to_string(),
        dry_run: false, // 关闭 dry-run 模式，使用真实的沙盒环境
        contact_email: Some("oldmos@gmail.com".to_string()),
        terms_of_service_agreed: true,
        ..Default::default()
    };
    
    // 创建 ACME 客户端
    let mut acme_client = AcmeClient::new(acme_config, account_key.clone())?;
    println!("✅ 成功创建 ACME 客户端 (沙盒模式)");
    
    // 注册账户
    let mut account_manager = acme_commander::acme::account::AccountManager::new(&mut acme_client);
    account_manager.register_account(Some("oldmos@gmail.com"), true, None).await?;
    println!("✅ 成功注册 ACME 账户 (测试环境)");
    
    Ok((acme_client, account_key))
}



/// 清理 DNS 记录
async fn cleanup_dns_records(
    dns_challenge_manager: &DnsChallengeManager,
    auth: &acme_commander::acme::Authorization,
) -> AcmeResult<()> {
    let cleanup_results = dns_challenge_manager.cleanup_challenge_records(
        &auth.identifier.value,
        false, // 关闭 dry-run 模式，使用真实的沙盒环境
    ).await?;
    
    println!("✅ 已清理 {} 条 DNS 记录", cleanup_results.len());
    for (i, result) in cleanup_results.iter().enumerate() {
        println!("  {}. 成功: {}", i + 1, result.success);
        if let Some(id) = &result.record_id {
            println!("     记录 ID: {}", id);
        }
    }
    
    Ok(())
}