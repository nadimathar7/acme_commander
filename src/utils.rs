//! ACME Commander 辅助工具函数
//!
//! 包含日志初始化、配置加载、版本信息显示等辅助功能

use std::path::PathBuf;
use std::error::Error;
use acme_commander::error::AcmeError;
use acme_commander::logger::{LogConfig, LogLevel, LogOutput, init_logger};
use rat_logger::info;
use crate::cli::LogOutputType;
/// 初始化日志系统
pub fn init_logging(
    verbose: bool,
    log_output: LogOutputType,
    log_file: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let log_level = if verbose {
        LogLevel::Debug
    } else {
        LogLevel::Info  // 默认使用 Info 级别显示重要信息
    };
    
    let log_output = match log_output {
        LogOutputType::Terminal => LogOutput::Terminal,
        LogOutputType::File => {
            let log_file = log_file
                .ok_or_else(|| "文件输出需要日志文件路径")?;
            LogOutput::File {
                log_dir: log_file.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf(),
                max_file_size: 10 * 1024 * 1024, // 10MB
                max_compressed_files: 5,
            }
        },
        LogOutputType::Both => {
            let log_file = log_file
                .ok_or_else(|| "双重输出需要日志文件路径")?;
            LogOutput::File {
                log_dir: log_file.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf(),
                max_file_size: 10 * 1024 * 1024, // 10MB
                max_compressed_files: 5,
            }
        },
    };
    
    let config = LogConfig {
        level: log_level,
        output: log_output,
        enabled: true,
        use_colors: true,
        use_emoji: true,
        show_timestamp: true,
        show_module: verbose,
        enable_async: false,
        batch_size: 2048,
        batch_interval_ms: 25,
        buffer_size: 16 * 1024,
    };

    init_logger(config)
        .map_err(|e| format!("初始化日志器失败: {}", e).into())
}

/// 加载配置文件
pub fn load_config(config_path: Option<PathBuf>) -> Result<crate::config::AcmeConfig, Box<dyn std::error::Error>> {
    use crate::config::{create_config_manager, load_config};

    let config = load_config(config_path, None)?;
    Ok(config)
}

/// 显示版本信息
pub fn show_version_info() {
    use rat_logger::info;
    
    info!("ACME Commander v{}", env!("CARGO_PKG_VERSION"));
    info!("构建信息:");
    if let Some(git_hash) = option_env!("GIT_HASH") {
        info!("  - Git提交: {}", git_hash);
    }
    if let Some(build_time) = option_env!("BUILD_TIME") {
        info!("  - 构建时间: {}", build_time);
    }
    info!("  - 目标平台: {}", std::env::consts::ARCH);
}



/// 格式化错误信息
pub fn format_error(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    
    while let Some(err) = source {
        message.push_str(&format!("\n  原因: {}", err));
        source = err.source();
    }
    
    message
}

/// 安全地显示令牌（隐藏敏感部分）
pub fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        "***".to_string()
    } else {
        format!("{}***{}", &token[..4], &token[token.len()-4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_token() {
        assert_eq!(mask_token("short"), "***");
        assert_eq!(mask_token("verylongtoken123456"), "very***3456");
        assert_eq!(mask_token("12345678"), "***");
        assert_eq!(mask_token("123456789"), "1234***6789");
    }

    #[test]
    fn test_format_error() {
        let error = std::io::Error::new(std::io::ErrorKind::NotFound, "文件未找到");
        let formatted = format_error(&error);
        assert!(formatted.contains("文件未找到"));
    }
}