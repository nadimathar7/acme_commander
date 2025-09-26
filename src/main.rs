//! ACME Commander 命令行工具
//!
//! 用于从 ACME 兼容的证书颁发机构（如 Let's Encrypt 和 ZeroSSL）获取和管理 SSL/TLS 证书的命令行工具。
//!
//! 该工具设计为 certbot 的替代品，具有以下特点：
//! - 专门使用 ECDSA P-384 (secp384r1) 密钥
//! - 专注于 DNS-01 挑战验证
//! - 支持 Cloudflare 
//! - 包含全面的 dry-run 功能
//! - 为支持的提供商提供令牌验证

mod cli;
mod commands;
mod utils;

use clap::{Parser, CommandFactory};

use acme_commander::error::AcmeError;
use acme_commander::logger::{LogConfig, LogLevel, LogOutput, init_logger};
use rat_logger::error;
use cli::{Cli, Commands};
use utils::{init_logging, load_config, show_version_info, format_error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // 初始化日志系统
    if let Err(e) = init_logging(cli.verbose, cli.log_output.clone(), cli.log_file.clone()) {
        eprintln!("❌ 日志初始化失败: {}", e);
        std::process::exit(1);
    }
    
    // 加载配置文件（如果提供）
    if let Err(e) = load_config(cli.config.clone()) {
        error!("配置文件加载失败: {}", e);
        std::process::exit(1);
    }
    
    // 显示版本信息（详细模式下）
    if cli.verbose {
        show_version_info();
    }
    

    
    // 如果没有提供子命令，显示帮助信息并正常退出
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // 显示帮助信息
            let mut cmd = Cli::command();
            cmd.print_help()?;
            return Ok(());
        }
    };
    
    // 执行命令
    let result = match command {
        Commands::Certonly { 
            domains, 
            email, 
            production, 
            dry_run, 
            dns_provider, 
            cloudflare_token, 
            account_key, 
            cert_key, 
            output_dir, 
            cert_name, 
            force_renewal 
        } => {
            commands::cmd_certonly(
                domains, email, production, dry_run, dns_provider, 
                cloudflare_token, account_key, cert_key, output_dir, 
                cert_name, force_renewal
            ).await
        },
        Commands::Renew { cert_dir, force, dry_run } => {
            commands::cmd_renew(cert_dir, force, dry_run).await
        },
        Commands::Recover { domain_dir, dry_run } => {
            commands::cmd_recover(domain_dir, dry_run).await
        },
        Commands::Validate { cloudflare_token, zerossl_api_key } => {
            commands::cmd_validate(cloudflare_token, zerossl_api_key).await
        },
        Commands::Keygen { output, key_type } => {
            commands::cmd_keygen(output, key_type).await
        },
        Commands::Show { cert_file, detailed } => {
            commands::cmd_show(cert_file, detailed).await
        },
        Commands::Revoke { cert_file, account_key, reason, production } => {
            commands::cmd_revoke(cert_file, account_key, reason, production).await
        },
        Commands::Dns { command } => {
            commands::cmd_dns(command).await
        },
    };
    
    // 处理执行结果
    if let Err(e) = result {
        let formatted_error = format_error(&e);
        error!("命令执行失败: {}", formatted_error);
        eprintln!("❌ 错误: {}", formatted_error);
        std::process::exit(1);
    }
    
    Ok(())
}