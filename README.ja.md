# ACME Commander

[![Crates.io](https://img.shields.io/crates/v/acme_commander.svg)](https://crates.io/crates/acme_commander)
[![Crates.io](https://img.shields.io/crates/d/acme_commander.svg)](https://crates.io/crates/acme_commander)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

[简体中文](README.md) | [English](README.en.md) | **日本語**

SSL/TLS 証明書の自動管理に特化したモダンな ACME クライアント。プロジェクト名は经典 RTS ゲーム「コマンド＆コンカー」の「コマンダー」役に由来し、自動証明書オーケストレーションを象徴しています。

## 🚀 コア機能

- **🔐 強制 ECDSA P-384**: secp384r1 鍵の専用使用、モダンな TLS ベストプラクティスに準拠
- **🌐 DNS-01 のみ**: DNS チャレンジ検証に特化、パブリック IP 不要
- **☁️ Cloudflare 統合**: Cloudflare DNS API のネイティブサポート
- **🔄 自動更新**: スマートな証明書ローテーション、ホットリロードサポート
- **🧪 ドライランモード**: 構成を検証するための安全なリハーサル機能
- **📊 詳細なロギング**: rat_logger ベースの高性能ロギングシステム
- **⚡ 高性能**: Tokio 非同期ランタイム上で構築
- **🌍 多言語サポート**: 中国語、日本語、英語の自動切り替え

## 📦 インストールとビルド

### 前提条件

- Rust 1.75+ (edition 2024)
- Cargo

### ビルド

```bash
# プロジェクトをクローン
git clone https://git.sukiyaki.su/0ldm0s/acme_commander
cd acme_commander

# リリース版をビルド
cargo build --release

# システムにインストール
cargo install --path .
```

## 🎯 クイックスタート

### 1. 新しい証明書の取得

```bash
# 基本的な使用法
acme-commander certonly \
  --domains example.com \
  --domains www.example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN

# 本番環境
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --production

# ドライランモード（初回使用推奨）
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --dry-run
```

### 2. 証明書の更新

```bash
# 自動スキャンと更新
acme-commander renew --cert-dir ./certs

# 全証明書を強制更新
acme-commander renew --cert-dir ./certs --force
```

### 3. DNS プロバイダーの検証

```bash
# Cloudflare トークンを検証
acme-commander validate --cloudflare-token YOUR_CF_TOKEN
```

### 4. 鍵の生成

```bash
# 証明書鍵を生成
acme-commander keygen --output cert.key --key-type certificate

# アカウント鍵を生成
acme-commander keygen --output account.key --key-type account
```

### 5. 証明書情報の表示

```bash
# 基本情報
acme-commander show cert.crt

# 詳細情報
acme-commander show cert.crt --detailed
```

### 6. 証明書の失効

```bash
acme-commander revoke cert.crt \
  --account-key account.key \
  --reason superseded \
  --production
```

## ⚙️ 設定オプション

### ロギング設定

```bash
# 詳細ロギングを有効化（デバッグレベル）
acme-commander --verbose certonly ...

# ファイルにログ出力
acme-commander --log-output file --log-file acme.log certonly ...

# 端末とファイルの両方に出力
acme-commander --log-output both --log-file acme.log certonly ...
```

## 📁 ファイル構造

デフォルトでは、証明書ファイルは `./certs` ディレクトリに保存されます：

```
certs/
├── cert.crt          # 証明書ファイル
├── cert.key          # 秘密鍵ファイル
├── cert-account.key  # アカウント鍵（自動生成の場合）
└── cert-chain.crt    # 完全な証明書チェーン（中間証明書を含む）
```

## 🔧 高度な使用法

### カスタム出力ディレクトリとファイル名

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --output-dir /etc/ssl/private \
  --cert-name example-com
```

### 既存の鍵を使用

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --account-key ./existing-account.key \
  --cert-key ./existing-cert.key
```

### 強制更新

```bash
acme-commander certonly \
  --domains example.com \
  --email admin@example.com \
  --cloudflare-token YOUR_CF_TOKEN \
  --force-renewal
```

## 🏗️ アーキテクチャ設計

### コアモジュール

- **`acme/`** - ACME プロトコル実装
- **`crypto/`** - 暗号アルゴリズムと鍵管理
- **`dns/`** - DNS プロバイダー統合
- **`certificate/`** - 証明書ライフサイクル管理
- **`auth/`** - 認証と承認
- **`config/`** - 設定管理

### 依存プロジェクト

- **`rat_logger`** - 高性能ロギングシステム
- **`rat_quickdns`** - DNS 解決最適化
- **`rat_quickmem`** - メモリ管理最適化

## 🔒 セキュリティ機能

- **強制 ECDSA P-384**: より高いセキュリティのための secp384r1 曲線を使用
- **DNS-01 検証**: HTTP-01 のセキュリティリスクを回避
- **鍵の分離**: アカウント鍵と証明書鍵の分離管理
- **安全なストレージ**: 機密データ保護のための `secrecy` クレートを使用
- **レート制限**: 組み込みの ACME サーバーレート制限保護

## 🚨 重要な注意事項

### 本番環境での使用

1. **初回使用はドライラン推奨**:
   ```bash
   acme-commander certonly --dry-run ...
   ```

2. **重要な鍵のバックアップ**:
   - アカウント鍵を失うと既存の証明書の管理ができなくなります
   - アカウント鍵は安全な場所に保存してください

3. **証明書の有効期限を監視**:
   - 自動更新のためのスケジュールタスクを設定
   - 成功を確認するために更新ログを監視

### Cloudflare トークンの権限

Cloudflare API トークンに以下の権限があることを確認してください：
- Zone:Zone:Read
- Zone:DNS:Edit
- 管理が必要なすべてのドメインを含む

## 📈 パフォーマンス最適化

- **非同期 I/O**: Tokio ベースの高性能非同期ランタイム
- **接続の再利用**: HTTP クライアント接続プール
- **メモリ最適化**: rat_quickmem メモリ管理を統合
- **DNS キャッシュ**: rat_quickdns を統合して DNS 解決を加速

## 🐛 トラブルシューティング

### 一般的な問題

1. **無効な Cloudflare トークン**
   ```bash
   # トークンを検証
   acme-commander validate --cloudflare-token YOUR_TOKEN
   ```

2. **DNS 伝播遅延**
   - ACME Commander は自動的に DNS 伝播を待機します
   - 失敗した場合、DNS レコードが正しく設定されているか確認してください

3. **レート制限**
   - Let's Encrypt には厳格なレート制限があります
   - デバッグにはテスト環境の使用を推奨

### デバッグモード

```bash
# 詳細なデバッグ情報を有効化
acme-commander --verbose certonly ...
```

## 👥 メンテナー

- **0ldm0s** <oldmos@gmail.com>

## 🔗 関連リンク

- [Let's Encrypt](https://letsencrypt.org/)
- [ACME RFC 8555](https://tools.ietf.org/html/rfc8555)
- [Cloudflare API](https://api.cloudflare.com/)

---

**ACME Commander** - SSL/TLS 証明書管理をシンプルかつ安全に。