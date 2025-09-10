# n0n - Enterprise-Grade Secure File Sharing

n0n is a comprehensive, cross-platform desktop application for secure file splitting, authenticated encryption, and enterprise storage management. It features a revolutionary multi-backend storage architecture with 11+ storage backends, advanced encryption at rest, usage analytics, quotas, and comprehensive configuration management.

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

### 🎛️ **Advanced GUI Features**
- **Modern UI** with comprehensive configuration interfaces
- **Real-time progress tracking** with pause/resume and cancellation
- **Drag-and-drop** file and folder selection
- **Folder watcher** with configurable debounce and filtering
- **Dry-run mode** with realistic progress simulation
- **Settings persistence** with non-secret data storage

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

### **Installation**
```bash
git clone https://github.com/your-org/n0n.git
cd n0n
cargo build --release
```

### **Run the Application**
```bash
cargo run
```

### **Basic Usage**
1. **Generate Keys**: Create or import encryption keypairs
2. **Configure Storage**: Select and configure your storage backend(s)
3. **Set Security**: Configure encryption, quotas, and analytics
4. **Process Files**: Split, encrypt, and store files securely
5. **Monitor**: View usage statistics and health metrics

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

## 🧪 **Testing**

### **Unit Tests**
```bash
cargo test
```

### **Integration Tests**
```bash
# Storage backend tests
cargo test --features integration-tests storage_backends

# SFTP integration (requires server)
export N0N_SFTP_HOST=test-server:22
export N0N_SFTP_USER=testuser
export N0N_SFTP_PASSWORD=testpass
cargo test --features sftp-tests sftp_integration
```

### **Backup & DR Tests**
```bash
# Test backup functionality
cargo test --features backup-tests backup_integration

# Test disaster recovery procedures
cargo test --features dr-tests disaster_recovery

# Test point-in-time recovery
cargo test --features recovery-tests point_in_time_recovery

# Test backup verification systems
cargo test --features verification-tests backup_verification

# End-to-end backup and restore tests
cargo test --release --features e2e-tests backup_restore_e2e
```

### **Benchmark Tests**
```bash
# Performance benchmarks
cargo bench

# Storage backend performance
cargo test --release --features benchmark-tests storage_performance

# Backup performance benchmarks
cargo bench --features backup-bench backup_performance
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

## 📚 **Documentation**

- **[Configuration Guide](docs/configuration.md)** - Complete configuration reference
- **[Storage Backends](docs/storage-backends.md)** - Backend-specific documentation
- **[Backup & Recovery Guide](docs/backup-recovery.md)** - Enterprise backup and disaster recovery
- **[Point-in-Time Recovery](docs/point-in-time-recovery.md)** - Detailed recovery procedures
- **[Disaster Recovery Planning](docs/disaster-recovery.md)** - DR planning and testing
- **[Security Guide](docs/security.md)** - Security best practices
- **[API Reference](docs/api.md)** - Developer API documentation
- **[Deployment Guide](docs/deployment.md)** - Production deployment
- **[Compliance Guide](docs/compliance.md)** - SOC2, ISO27001, and regulatory compliance

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

### **Development Setup**
```bash
git clone https://github.com/your-org/n0n.git
cd n0n
cargo build
cargo test
cargo run
```

## 📄 **License**

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## 🆘 **Support**

- **Issues**: [GitHub Issues](https://github.com/your-org/n0n/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/n0n/discussions)
- **Security**: security@example.com

---

**n0n** - Enterprise-grade secure file sharing with multi-cloud storage, advanced encryption, comprehensive backup & disaster recovery, and enterprise management tools for mission-critical data protection.