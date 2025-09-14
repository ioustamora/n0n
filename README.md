# n0n - Enterprise-Grade Secure File Synchronization & Storage

n0n is a modern, enterprise-grade secure file synchronization and storage solution built in Rust. It provides comprehensive data protection through advanced encryption, multi-backend storage architecture, real-time monitoring, and disaster recovery capabilities. Designed for organizations requiring secure, scalable, and auditable file management systems.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-enterprise--grade-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)]()

## 🎯 **Overview**

n0n addresses critical enterprise needs for secure file management with a modular architecture that scales from individual developers to large organizations. Built with security-first principles, it provides military-grade encryption, comprehensive audit trails, and flexible deployment options.

## 🚀 Key Features

### 🔐 **Advanced Security**
- **Per-chunk authenticated encryption** using X25519 + XSalsa20-Poly1305 (libsodium crypto_box)
- **Encryption at rest** with multiple algorithms (XSalsa20Poly1305, ChaCha20Poly1305, AES256GCM)
- **Key management** with password-based key derivation (Argon2)
- **Host fingerprint verification** for SFTP connections
- **Environment-based security levels** (Development/Testing/Staging/Production)

### 🏗️ **Multi-Backend Storage Architecture**
- **11 Storage Backends**: Local, SFTP, S3-compatible, Google Cloud, Azure Blob, PostgreSQL, Redis, WebDAV, IPFS, MultiCloud, CachedCloud
- **Multi-cloud replication** with configurable consistency levels (Eventual, Strong, Quorum)
- **Intelligent caching** with multiple eviction policies and write strategies
- **Storage migration tools** with progress tracking and verification
- **Health monitoring** and automatic failover

### 📊 **Analytics & Monitoring**
- **Usage analytics** with time-based metrics and operation tracking
- **Quota management** with size limits, operation limits, and enforcement policies
- **Real-time monitoring** with health checks and performance metrics
- **Comprehensive reporting** with daily/hourly breakdowns and trend analysis

### ⚙️ **Configuration Management**
- **Configuration profiles** with environment-specific overrides
- **Schema-based validation** with custom rules and cross-field validation
- **Import/Export** in multiple formats (JSON, YAML, TOML, encrypted archives)
- **Environment management** for development, testing, staging, and production
- **Feature flags** and environment variables per deployment environment

### 🎛️ **Modern Desktop Interface**
- **Cross-platform GUI** built with egui for native performance
- **Enterprise dashboard** with real-time monitoring and alerts
- **Drag-and-drop** file operations with progress tracking
- **Configuration wizards** for guided setup of complex features
- **Role-based access control** interface with hierarchical permissions
- **Real-time collaboration** tools for team environments
- **Dark/light theme** support with accessibility features

### 🗄️ **Backup & Disaster Recovery**
- **Automated backup scheduling** with multiple strategies (Full, Incremental, Differential, Continuous)
- **Point-in-time recovery** with precise restore capabilities to any historical moment
- **Comprehensive backup verification** with multi-phase integrity checking and restore testing
- **Disaster recovery planning** with automated testing and emergency procedures
- **Multi-backend backup support** across all storage types with cross-replication
- **Retention policies** with intelligent cleanup and long-term archival
- **Recovery Time/Point Objectives** (RTO/RPO) monitoring and compliance tracking

## 🏢 **Enterprise Features**

### **Storage Backends**

| Backend | Description | Use Case |
|---------|-------------|----------|
| **Local** | High-performance local filesystem | Development, testing |
| **SFTP** | Secure file transfer with SSH keys | Remote servers, legacy systems |
| **S3-Compatible** | AWS S3, MinIO, Cloudflare R2, DigitalOcean | Cloud storage, CDNs |
| **Google Cloud** | Google Cloud Storage with service accounts | Google Cloud Platform |
| **Azure Blob** | Microsoft Azure Blob Storage | Microsoft Azure |
| **PostgreSQL** | Database storage with ACID guarantees | Structured data, transactions |
| **Redis** | High-performance in-memory storage | Caching, session storage |
| **WebDAV** | Nextcloud, ownCloud, SharePoint | Collaborative platforms |
| **IPFS** | Decentralized peer-to-peer storage | Blockchain, decentralization |
| **MultiCloud** | Replication across multiple backends | High availability, disaster recovery |
| **CachedCloud** | Performance-optimized caching layer | Hybrid cloud-local performance |

### **Advanced Capabilities**

- **Storage Migration**: Move data between any backends with verification and integrity checking
- **Encryption Layers**: Apply encryption to any storage backend transparently with multiple algorithms
- **Analytics Wrappers**: Add monitoring, quotas, and usage tracking to any backend
- **Configuration Profiles**: Environment-specific settings with schema validation and import/export
- **Backup & Recovery**: Enterprise-grade backup scheduling with point-in-time recovery capabilities
- **Disaster Recovery**: Complete DR planning with automated testing and emergency procedures
- **Verification Systems**: Multi-phase backup verification with restore capability testing
- **Retention Management**: Intelligent data lifecycle management with customizable retention policies

## 🚀 **Quick Start**

### **Prerequisites**
- Rust 1.70+ with Cargo
- For GUI: System dependencies (see [GUI Dependencies](#gui-dependencies))
- For enterprise features: Database access and cloud credentials

### **Installation**
```bash
# Clone the repository
git clone https://github.com/your-org/n0n.git
cd n0n

# Build optimized release
cargo build --release

# Run tests to verify installation
cargo test
```

### **Launch Application**
```bash
# GUI application
cargo run

# CLI mode (headless)
cargo run --features="cli-only"

# With specific configuration
cargo run -- --config production.toml
```

### **First-Time Setup**
1. **🔑 Security Setup**: Generate encryption keypairs or import existing ones
2. **☁️ Storage Configuration**: Connect to your preferred storage backend(s)
3. **👥 Access Control**: Set up user roles and permissions (if multi-user)
4. **📊 Monitoring**: Configure analytics and alerting preferences
5. **🔄 Backup Strategy**: Schedule automated backups and disaster recovery plans

### **GUI Dependencies**
**Ubuntu/Debian:**
```bash
sudo apt-get install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

**Fedora:**
```bash
sudo dnf install libxcb-devel libxkbcommon-devel openssl-devel
```

**Windows:**
```bash
# No additional dependencies required
```

**macOS:**
```bash
# Install via Homebrew
brew install openssl
```

### **Advanced Configuration**
```bash
# Create configuration profile
n0n config create-profile production "Production environment settings"

# Set environment
n0n config set-environment production

# Configure storage backend
n0n storage configure s3 --bucket my-bucket --region us-east-1

# Enable encryption at rest
n0n encryption enable --algorithm XSalsa20Poly1305 --password-prompt

# Set quotas
n0n quota set --max-size 1TB --max-operations 10000/day

# Configure automated backups
n0n backup create-schedule "Daily Production Backup" \
    --strategy full --frequency daily --hour 2 \
    --source s3-primary --destination s3-backup \
    --retention 30d --compression --verification

# Create disaster recovery plan
n0n dr create-plan "Production DR Plan" \
    --rto 4h --rpo 1h \
    --backup-schedules "Daily Production Backup" \
    --contact "ops-team@company.com" \
    --test-schedule weekly
```

## 📋 **Storage Backend Configuration**

### **S3-Compatible Storage**
```bash
# AWS S3
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
n0n storage configure s3 --bucket my-bucket --region us-east-1

# MinIO
n0n storage configure s3 --bucket my-bucket --endpoint http://localhost:9000 \
    --access-key minioadmin --secret-key minioadmin

# Cloudflare R2
n0n storage configure s3 --bucket my-bucket \
    --endpoint https://your-account.r2.cloudflarestorage.com
```

### **Google Cloud Storage**
```bash
# Service account authentication
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
n0n storage configure gcs --bucket my-bucket --project-id my-project
```

### **SFTP with SSH Keys**
```bash
n0n storage configure sftp --host server.example.com:22 \
    --user myuser --private-key ~/.ssh/id_ed25519 \
    --host-fingerprint SHA256:your-host-fingerprint
```

### **Multi-Cloud Replication**
```bash
# Configure primary and replica backends
n0n storage configure multicloud --primary s3-primary \
    --replicas s3-backup,gcs-backup --consistency strong
```

## 🔒 **Security Model**

### **Encryption Architecture**
1. **Application-Level Encryption**: Files encrypted before reaching storage
2. **Per-Chunk Encryption**: Each chunk encrypted with unique nonce
3. **Encryption at Rest**: Additional layer encrypts data at storage backend
4. **Key Management**: Secure key derivation and storage

### **Authentication & Authorization**
- **Public-key cryptography** for recipient-specific encryption
- **SSH key authentication** for SFTP backends
- **Service account authentication** for cloud providers
- **Host fingerprint verification** for secure connections

### **Security Best Practices**
- **Environment-specific security levels**
- **Automatic security validation**
- **Secure configuration management**
- **Audit logging and monitoring**

## 📊 **Monitoring & Analytics**

### **Usage Metrics**
- Total chunks and storage size
- Operations per hour/day/month
- Average chunk sizes and patterns
- Backend performance metrics

### **Health Monitoring**
- Backend connectivity and latency
- Error rates and retry statistics
- Storage capacity and quota usage
- System resource utilization

### **Reporting**
```bash
# Generate usage report
n0n analytics report --days 30 --format json > usage-report.json

# Export metrics for external monitoring
n0n analytics export --format prometheus
```

## 🛠️ **Advanced Features**

### **Backup & Disaster Recovery**
```bash
# Create backup schedule with multiple strategies
n0n backup create-schedule "Incremental Hourly" \
    --strategy incremental --frequency hourly \
    --source local-primary --destination s3-backup \
    --retention 7d --compression

# Point-in-time recovery
n0n backup restore --backend s3-backup \
    --target-time "2024-01-01T12:00:00Z" \
    --restore-path /recovery/data

# Verify backup integrity
n0n backup verify --backup-id backup_20240101_120000 \
    --comprehensive --restore-test

# Test disaster recovery plan
n0n dr test-plan "Production DR Plan" \
    --simulate-failures --generate-report

# Get recovery points for point-in-time restore
n0n backup list-recovery-points --backend s3-backup \
    --date-range "last-30-days"
```

### **Storage Migration**
```bash
# Migrate between backends with verification
n0n migrate --source local-dev --destination s3-prod \
    --strategy streaming --verify-integrity
```

### **Configuration Management**
```bash
# Export configuration bundle
n0n config export --format encrypted --password-prompt \
    --output production-config.n0n

# Import configuration
n0n config import --file staging-config.n0n --password-prompt
```

### **Enterprise Backup & Recovery**
```bash
# Create comprehensive backup schedule
n0n backup create-schedule "Enterprise Backup" \
    --strategy differential --frequency "daily@02:00" \
    --source multicloud-primary --destination s3-backup \
    --retention "30d,4w,12m" --compression gzip \
    --encryption XSalsa20Poly1305 --verification comprehensive

# Multi-tier backup strategy
n0n backup create-schedule "Continuous Protection" \
    --strategy continuous --frequency "5min" \
    --source local-hot --destination redis-cache \
    --retention "24h" --rpo "5min"

# Cross-region disaster recovery backup
n0n backup create-schedule "DR Backup" \
    --strategy full --frequency weekly \
    --source s3-primary --destination gcs-dr \
    --retention "1y" --verification restore-test

# Point-in-time recovery with precision
n0n backup restore --backend s3-backup \
    --target-time "2024-01-01T14:30:15Z" \
    --restore-path /recovery/precise-restore \
    --verify-integrity --progress

# Bulk recovery point management
n0n backup list-recovery-points --backend all \
    --filter "status:verified,age:<30d" \
    --format table --sort-by date-desc
```

### **Disaster Recovery & Business Continuity**
```bash
# Create enterprise disaster recovery plan
n0n dr create-plan "Production DR Plan" \
    --name "Critical System Recovery" \
    --rto "4h" --rpo "1h" \
    --backup-schedules "Enterprise Backup,DR Backup" \
    --contacts "ops-team@company.com,cto@company.com" \
    --test-schedule "monthly"

# Add recovery procedures to DR plan
n0n dr add-procedure "Production DR Plan" \
    --step 1 --title "Verify Backup Integrity" \
    --description "Validate latest backup before restore" \
    --duration "15min" --automation-script "verify_backups.sh"

n0n dr add-procedure "Production DR Plan" \
    --step 2 --title "Provision DR Infrastructure" \
    --description "Spin up disaster recovery environment" \
    --duration "30min" --resources "compute:8vcpu,storage:1TB"

# Test disaster recovery plan
n0n dr test-plan "Production DR Plan" \
    --simulate-failures --dry-run \
    --report-format "detailed" --export "dr-test-report.pdf"

# Execute disaster recovery (emergency use)
n0n dr execute-plan "Production DR Plan" \
    --incident-id "INC-2024-001" \
    --restore-target "/dr/recovery-site" \
    --notify-contacts --monitor-progress

# Monitor DR plan readiness
n0n dr status --plan "Production DR Plan" \
    --show-metrics --backup-health --test-history

# Generate compliance reports
n0n dr compliance-report --plan "Production DR Plan" \
    --standards "SOC2,ISO27001" \
    --period "last-quarter" \
    --export "compliance-report.json"
```

## 🧪 **Testing & Quality Assurance**

### **Test Suite Overview**
n0n includes comprehensive testing across multiple dimensions:
- **Unit Tests**: Core functionality and algorithms
- **Integration Tests**: Storage backends and external services
- **Security Tests**: Encryption, access control, and audit trails
- **Performance Tests**: Benchmarks and load testing
- **End-to-End Tests**: Complete workflows and disaster recovery scenarios

### **Running Tests**

#### **Basic Test Suite**
```bash
# Run all unit tests
cargo test

# Run with output for debugging
cargo test -- --nocapture

# Run specific test module
cargo test crypto::tests
```

#### **Integration Tests**
```bash
# All integration tests (requires external services)
cargo test --features integration-tests

# Storage backend integration tests
cargo test --features integration-tests storage_backends

# SFTP integration (requires test server)
export N0N_SFTP_HOST=test-server:22
export N0N_SFTP_USER=testuser
export N0N_SFTP_PASSWORD=testpass
cargo test --features sftp-tests sftp_integration

# Cloud storage tests (requires credentials)
export AWS_ACCESS_KEY_ID=test-key
export AWS_SECRET_ACCESS_KEY=test-secret
cargo test --features aws-tests s3_integration
```

#### **Security & Compliance Tests**
```bash
# Cryptographic algorithm validation
cargo test --features crypto-validation crypto_compliance

# Access control and audit tests
cargo test --features security-tests access_control_suite

# Memory safety and secure deletion
cargo test --features memory-tests secure_memory_handling
```

#### **Performance & Load Testing**
```bash
# Benchmark suite
cargo bench

# Storage performance benchmarks
cargo bench --features benchmark-tests storage_performance

# Encryption performance testing
cargo bench crypto_benchmarks

# Large file handling tests
cargo test --release --features load-tests large_file_processing
```

#### **Disaster Recovery Testing**
```bash
# Backup system validation
cargo test --features backup-tests backup_integration

# Disaster recovery procedures
cargo test --features dr-tests disaster_recovery

# Point-in-time recovery validation
cargo test --features recovery-tests point_in_time_recovery

# Backup integrity verification
cargo test --features verification-tests backup_verification

# Complete backup/restore workflows
cargo test --release --features e2e-tests backup_restore_e2e
```

### **Continuous Integration**
```bash
# CI test suite (runs on all platforms)
./scripts/ci-test.sh

# Security audit
cargo audit

# Code coverage report
cargo tarpaulin --out Html
```

## 🏗️ **Architecture**

### **Layered Design**
```
┌─────────────────────────────────────┐
│            GUI Layer                │
├─────────────────────────────────────┤
│      Configuration Management       │
├─────────────────────────────────────┤
│   Backup & Disaster Recovery Layer  │
├─────────────────────────────────────┤
│    Analytics & Monitoring Layer     │
├─────────────────────────────────────┤
│      Encryption at Rest Layer       │
├─────────────────────────────────────┤
│      Storage Abstraction Layer      │
├─────────────────────────────────────┤
│     Storage Backend Implementations │
└─────────────────────────────────────┘
```

### **Key Components**
- **Storage Factory**: Creates and manages backend instances
- **Migration Manager**: Handles data movement between backends
- **Backup Manager**: Orchestrates backup scheduling, execution, and verification
- **Disaster Recovery Engine**: Manages DR plans, testing, and execution
- **Analytics Manager**: Tracks usage and enforces quotas
- **Configuration Manager**: Manages profiles and environments
- **Encryption Manager**: Handles encryption at rest
- **Verification Engine**: Performs multi-phase backup integrity checking
- **Recovery Engine**: Handles point-in-time recovery and restore operations

## 📚 **Documentation & Resources**

### **User Guides**
- **[Getting Started Guide](docs/getting-started.md)** - Step-by-step setup and first use
- **[Configuration Reference](docs/configuration.md)** - Complete configuration options
- **[Storage Backend Guide](docs/storage-backends.md)** - Backend setup and optimization
- **[Security Best Practices](docs/security.md)** - Security configuration and hardening
- **[Troubleshooting Guide](docs/troubleshooting.md)** - Common issues and solutions

### **Enterprise Documentation**
- **[Deployment Guide](docs/deployment.md)** - Production deployment strategies
- **[Backup & Recovery Manual](docs/backup-recovery.md)** - Enterprise backup and disaster recovery
- **[Disaster Recovery Planning](docs/disaster-recovery.md)** - DR planning, testing, and execution
- **[Compliance Guide](docs/compliance.md)** - SOC2, ISO27001, GDPR, and regulatory compliance
- **[Access Control & RBAC](docs/access-control.md)** - User management and permissions

### **Developer Resources**
- **[API Reference](docs/api.md)** - Complete API documentation
- **[Plugin Development](docs/plugins.md)** - Creating custom storage backends and widgets
- **[Contributing Guide](CONTRIBUTING.md)** - Development setup and contribution guidelines
- **[Architecture Overview](docs/architecture.md)** - System design and component interactions
- **[Performance Tuning](docs/performance.md)** - Optimization and scaling strategies

### **Additional Resources**
- **[FAQ](docs/faq.md)** - Frequently asked questions
- **[Release Notes](CHANGELOG.md)** - Version history and breaking changes
- **[Migration Guide](docs/migration.md)** - Upgrading between major versions
- **[Examples Repository](examples/)** - Sample configurations and use cases

## 🤝 **Contributing**

We welcome contributions from the community! n0n is built with security and reliability as core principles, so we maintain high standards for code quality and testing.

### **How to Contribute**
1. **🍴 Fork** the repository and create a feature branch
2. **🔧 Develop** your feature with comprehensive tests
3. **📝 Document** your changes and update relevant documentation
4. **🧪 Test** thoroughly across different platforms and scenarios
5. **📤 Submit** a pull request with detailed description

### **Development Environment Setup**
```bash
# Clone your fork
git clone https://github.com/your-username/n0n.git
cd n0n

# Install development dependencies
cargo install cargo-watch cargo-audit cargo-tarpaulin

# Run development build with hot reload
cargo watch -x run

# Run full test suite
cargo test --all-features

# Check security vulnerabilities
cargo audit

# Generate test coverage report
cargo tarpaulin --out Html
```

### **Contribution Guidelines**
- **Security First**: All changes must maintain or improve security posture
- **Test Coverage**: New features require >= 80% test coverage
- **Documentation**: Public APIs must be documented with examples
- **Performance**: Changes affecting performance need benchmark comparisons
- **Cross-Platform**: Ensure compatibility across Windows, macOS, and Linux

### **Development Priorities**
We're particularly interested in contributions in these areas:
1. **🎨 UI/UX Improvements**: Enhanced user experience and accessibility
2. **🔒 Security Features**: Advanced cryptographic operations and compliance
3. **☁️ Storage Backends**: New cloud providers and storage systems
4. **🌐 Internationalization**: Multi-language support and localization
5. **📱 Mobile Support**: Touch-friendly interfaces and mobile backends
6. **🔌 Plugin Architecture**: Extensibility and custom integrations

## 📄 **License**

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## 🆘 **Support & Community**

### **Getting Help**
- **📖 Documentation**: Check our [comprehensive docs](docs/) first
- **❓ GitHub Discussions**: [Community Q&A and general discussions](https://github.com/your-org/n0n/discussions)
- **🐛 Issues**: [Report bugs and feature requests](https://github.com/your-org/n0n/issues)
- **💬 Discord**: Join our [Discord community](https://discord.gg/n0n-community) for real-time chat

### **Enterprise Support**
- **🏢 Enterprise Licensing**: enterprise@n0n.io
- **🛠️ Professional Services**: consulting@n0n.io
- **🚨 Priority Support**: support@n0n.io
- **🔒 Security Issues**: security@n0n.io (GPG key available)

### **Community Resources**
- **🎥 Tutorials**: [YouTube Channel](https://youtube.com/n0n-tutorials)
- **📝 Blog**: [Technical blog and case studies](https://blog.n0n.io)
- **🐦 Twitter**: [@n0n_project](https://twitter.com/n0n_project) for updates
- **📺 Demos**: [Live demos and webinars](https://n0n.io/demos)

---

<div align="center">

**n0n** - Enterprise-grade secure file synchronization and storage

*Built with 🦀 Rust • Secured with 🔒 Military-grade encryption • Designed for 🏢 Enterprise scale*

[**Documentation**](docs/) • [**Quick Start**](#-quick-start) • [**Community**](https://github.com/your-org/n0n/discussions) • [**Enterprise**](https://n0n.io/enterprise)

</div>