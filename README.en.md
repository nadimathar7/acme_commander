# ACME Commander

[![Crates.io](https://img.shields.io/crates/v/acme_commander.svg)](https://crates.io/crates/acme_commander)
[![Crates.io](https://img.shields.io/crates/d/acme_commander.svg)](https://crates.io/crates/acme_commander)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

[简体中文](README.md) | **English** | [日本語](README.ja.md)

A modern ACME client focused on automated SSL/TLS certificate management. The project name is inspired by the "Commander" role from the classic RTS game "Command & Conquer", symbolizing automated certificate orchestration.

## 🚀 Core Features

- **🔐 Mandatory ECDSA P-384**: Dedicated use of secp384r1 keys, following modern TLS best practices
- **🌐 DNS-01 Only**: Focused on DNS challenge validation, no public IP required
- **☁️ Cloudflare Integration**: Native support for Cloudflare DNS API
- **🔄 Auto Renewal**: Smart certificate rotation with hot reload support
- **🧪 Dry-Run Mode**: Safe rehearsal functionality to verify configurations
- **📊 Detailed Logging**: High-performance logging system based on rat_logger
- **⚡ High Performance**: Built on Tokio async runtime
- **🌍 Multi-language Support**: Automatic switching between Chinese, Japanese, and English

## 📦 Installation & Build

### Prerequisites

- Rust 1.75+ (edition 2024)
- Cargo

### Building

```bash
# Clone the project
git clone https://git.sukiyaki.su/0ldm0s/acme_commander
cd acme_commander

# Build release version
cargo build --release

# Install to system
cargo install --path .
```

## 🎯 Quick Start

### 1. Get New Certificate

```bash
# Basic usage
acme-commander certonly \
  --domains example.com \
  --domains www.example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN

# Production environment
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --production

# Dry-run mode (recommended for first use)
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --dry-run
```

### 2. Renew Certificate

```bash
# Auto scan and renew
acme-commander renew --cert-dir ./certs

# Force renew all certificates
acme-commander renew --cert-dir ./certs --force
```

### 3. Validate DNS Provider

```bash
# Validate Cloudflare Token
acme-commander validate --cloudflare-token YOUR_CF_TOKEN
```

### 4. Generate Keys

```bash
# Generate certificate key
acme-commander keygen --output cert.key --key-type certificate

# Generate account key
acme-commander keygen --output account.key --key-type account
```

### 5. View Certificate Information

```bash
# Basic information
acme-commander show cert.crt

# Detailed information
acme-commander show cert.crt --detailed
```

### 6. Revoke Certificate

```bash
acme-commander revoke cert.crt \
  --account-key account.key \
  --reason superseded \
  --production
```

## ⚙️ Configuration Options

### Logging Configuration

```bash
# Enable verbose logging (debug level)
acme-commander --verbose certonly ...

# Log output to file
acme-commander --log-output file --log-file acme.log certonly ...

# Output to both terminal and file
acme-commander --log-output both --log-file acme.log certonly ...
```

## 📁 File Structure

By default, certificate files are saved in the `./certs` directory:

```
certs/
├── cert.crt          # Certificate file
├── cert.key          # Private key file
├── cert-account.key  # Account key (if auto-generated)
└── cert-chain.crt    # Full certificate chain (includes intermediate certificates)
```

## 🔧 Advanced Usage

### Custom Output Directory and Filename

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --output-dir /etc/ssl/private \
  --cert-name example-com
```

### Using Existing Keys

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --account-key ./existing-account.key \
  --cert-key ./existing-cert.key
```

### Force Renewal

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --force-renewal
```

## 🏗️ Architecture Design

### Core Modules

- **`acme/`** - ACME protocol implementation
- **`crypto/`** - Cryptographic algorithms and key management
- **`dns/`** - DNS provider integration
- **`certificate/`** - Certificate lifecycle management
- **`auth/`** - Authentication and authorization
- **`config/`** - Configuration management

### Dependency Projects

- **`rat_logger`** - High-performance logging system
- **`rat_quickdns`** - DNS resolution optimization
- **`rat_quickmem`** - Memory management optimization

## 🔒 Security Features

- **Mandatory ECDSA P-384**: Uses secp384r1 curve for higher security
- **DNS-01 Validation**: Avoids security risks of HTTP-01
- **Key Isolation**: Separate management of account and certificate keys
- **Secure Storage**: Uses `secrecy` crate to protect sensitive data
- **Rate Limiting**: Built-in ACME server rate limiting protection

## 🚨 Important Notes

### Production Usage

1. **Dry-run recommended for first use**:
   ```bash
   acme-commander certonly --dry-run ...
   ```

2. **Backup important keys**:
   - Loss of account key will prevent management of existing certificates
   - Store account keys in a secure location

3. **Monitor certificate expiration**:
   - Set up scheduled tasks for automatic renewal
   - Monitor renewal logs to ensure success

### Cloudflare Token Permissions

Ensure Cloudflare API Token has the following permissions:
- Zone:Zone:Read
- Zone:DNS:Edit
- Include all domains that need management

## 📈 Performance Optimization

- **Async I/O**: High-performance async runtime based on Tokio
- **Connection Reuse**: HTTP client connection pool
- **Memory Optimization**: Integrated rat_quickmem memory management
- **DNS Caching**: Integrated rat_quickdns for accelerated DNS resolution

## 🐛 Troubleshooting

### Common Issues

1. **Invalid Cloudflare Token**
   ```bash
   # Validate token
   acme-commander validate --cloudflare-token YOUR_TOKEN
   ```

2. **DNS Propagation Delay**
   - ACME Commander automatically waits for DNS propagation
   - If failed, check if DNS records are correctly set

3. **Rate Limiting**
   - Let's Encrypt has strict rate limits
   - Recommended to use test environment for debugging

### Debug Mode

```bash
# Enable detailed debugging information
acme-commander --verbose certonly ...
```

## 👥 Maintainers

- **0ldm0s** <oldmos@gmail.com>

## 🔗 Related Links

- [Let's Encrypt](https://letsencrypt.org/)
- [ACME RFC 8555](https://tools.ietf.org/html/rfc8555)
- [Cloudflare API](https://api.cloudflare.com/)

---

**ACME Commander** - Making SSL/TLS certificate management simple and secure.