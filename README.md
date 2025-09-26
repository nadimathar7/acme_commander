# ACME Commander

一个现代化的 ACME 客户端，专注于 SSL/TLS 证书的自动化管理。项目名取自经典 RTS 游戏《Command & Conquer》的"指挥官"角色，寓意自动化证书调度。

## 🚀 核心特性

- **🔐 强制 ECDSA P-384**：专门使用 secp384r1 密钥，符合现代 TLS 最佳实践
- **🌐 DNS-01 专用**：专注于 DNS 挑战验证，无需公网 IP
- **☁️ Cloudflare 集成**：原生支持 Cloudflare DNS API
- **🔄 自动续期**：智能证书轮转，支持热加载
- **🧪 Dry-Run 模式**：安全的演练功能，验证配置无误
- **📊 详细日志**：基于 rat_logger 的高性能日志系统
- **⚡ 高性能**：基于 Tokio 异步运行时

## 📦 安装与构建

### 前置要求

- Rust 1.75+ (edition 2024)
- Cargo

### 构建

```bash
# 克隆项目
git clone https://git.sukiyaki.su/0ldm0s/acme_commander
cd acme_commander

# 构建发布版本
cargo build --release

# 安装到系统
cargo install --path .
```

## 🎯 快速开始

### 1. 获取新证书

```bash
# 基本用法
acme-commander certonly \
  --domains example.com \
  --domains www.example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN

# 生产环境
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --production

# 演练模式（推荐首次使用）
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --dry-run
```

### 2. 续订证书

```bash
# 自动扫描并续订
acme-commander renew --cert-dir ./certs

# 强制续订所有证书
acme-commander renew --cert-dir ./certs --force
```

### 3. 验证 DNS 提供商

```bash
# 验证 Cloudflare Token
acme-commander validate cloudflare --cloudflare-token YOUR_CF_TOKEN
```

### 4. 生成密钥

```bash
# 生成证书密钥
acme-commander keygen --output cert.key --key-type certificate

# 生成账户密钥
acme-commander keygen --output account.key --key-type account
```

### 5. 查看证书信息

```bash
# 基本信息
acme-commander show cert.crt

# 详细信息
acme-commander show cert.crt --detailed
```

### 6. 撤销证书

```bash
acme-commander revoke cert.crt \
  --account-key account.key \
  --reason superseded \
  --production
```

## ⚙️ 配置选项

### 日志配置

```bash
# 启用详细日志
acme-commander --verbose certonly ...

# 启用调试日志
acme-commander --debug certonly ...

# 日志输出到文件
acme-commander --log-output file --log-file acme.log certonly ...

# 同时输出到终端和文件
acme-commander --log-output both --log-file acme.log certonly ...
```

## 📁 文件结构

默认情况下，证书文件将保存在 `./certs` 目录：

```
certs/
├── cert.crt          # 证书文件
├── cert.key          # 私钥文件
├── cert-account.key  # 账户密钥（如果自动生成）
└── cert-chain.crt    # 完整证书链（包含中间证书）
```

## 🔧 高级用法

### 自定义输出目录和文件名

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --output-dir /etc/ssl/private \
  --cert-name example-com
```

### 使用现有密钥

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --account-key ./existing-account.key \
  --cert-key ./existing-cert.key
```

### 强制续订

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --force-renewal
```

## 🏗️ 架构设计

### 核心模块

- **`acme/`** - ACME 协议实现
- **`crypto/`** - 加密算法和密钥管理
- **`dns/`** - DNS 提供商集成
- **`certificate/`** - 证书生命周期管理
- **`auth/`** - 认证和授权
- **`config/`** - 配置管理

### 依赖项目

- **`rat_logger`** - 高性能日志系统
- **`rat_quickdns`** - DNS 解析优化
- **`rat_quickmem`** - 内存管理优化

## 🔒 安全特性

- **强制 ECDSA P-384**：使用 secp384r1 曲线，提供更高的安全性
- **DNS-01 验证**：避免 HTTP-01 的安全风险
- **密钥隔离**：账户密钥和证书密钥分离管理
- **安全存储**：使用 `secrecy` crate 保护敏感数据
- **速率限制**：内置 ACME 服务器速率限制保护

## 🚨 注意事项

### 生产环境使用

1. **首次使用建议先进行 dry-run**：
   ```bash
   acme-commander certonly --dry-run ...
   ```

2. **备份重要密钥**：
   - 账户密钥丢失将无法管理现有证书
   - 建议将账户密钥存储在安全位置

3. **监控证书过期**：
   - 设置定时任务自动续期
   - 监控续期日志确保成功

### Cloudflare Token 权限

确保 Cloudflare API Token 具有以下权限：
- Zone:Zone:Read
- Zone:DNS:Edit
- 包含所有需要管理的域名

## 📈 性能优化

- **异步 I/O**：基于 Tokio 的高性能异步运行时
- **连接复用**：HTTP 客户端连接池
- **内存优化**：集成 rat_quickmem 内存管理
- **DNS 缓存**：集成 rat_quickdns 加速 DNS 解析

## 🐛 故障排除

### 常见问题

1. **Cloudflare Token 无效**
   ```bash
   # 验证 token
   acme-commander validate cloudflare --cloudflare-token YOUR_TOKEN
   ```

2. **DNS 传播延迟**
   - ACME Commander 会自动等待 DNS 传播
   - 如果失败，请检查 DNS 记录是否正确设置

3. **速率限制**
   - Let's Encrypt 有严格的速率限制
   - 建议使用测试环境进行调试

### 调试模式

```bash
# 启用详细调试信息
RUST_LOG=debug acme-commander --debug certonly ...
```

## 👥 维护者

- **0ldm0s** <oldmos@gmail.com>

## 🔗 相关链接

- [Let's Encrypt](https://letsencrypt.org/)
- [ACME RFC 8555](https://tools.ietf.org/html/rfc8555)
- [Cloudflare API](https://api.cloudflare.com/)

---

**ACME Commander** - 让 SSL/TLS 证书管理变得简单而安全。