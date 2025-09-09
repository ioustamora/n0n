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

- **Storage Migration**: Move data between any backends with verification
- **Encryption Layers**: Apply encryption to any storage backend transparently
- **Analytics Wrappers**: Add monitoring and quotas to any backend
- **Configuration Profiles**: Environment-specific settings with validation
- **Backup & Recovery**: Automated backup scheduling and point-in-time recovery
- **Disaster Recovery**: Multi-region replication and failover procedures

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

### **Backup & Recovery**
```bash
# Schedule automated backups
n0n backup schedule --frequency daily --retention 30d \
    --destination s3-backup

# Restore from backup
n0n backup restore --date 2024-01-01 --destination local-restore
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

### **Benchmark Tests**
```bash
# Performance benchmarks
cargo bench

# Storage backend performance
cargo test --release --features benchmark-tests storage_performance
```

## 🏗️ **Architecture**

### **Layered Design**
```
┌─────────────────────────────────────┐
│            GUI Layer                │
├─────────────────────────────────────┤
│      Configuration Management       │
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
- **Analytics Manager**: Tracks usage and enforces quotas
- **Configuration Manager**: Manages profiles and environments
- **Encryption Manager**: Handles encryption at rest

## 📚 **Documentation**

- **[Configuration Guide](docs/configuration.md)** - Complete configuration reference
- **[Storage Backends](docs/storage-backends.md)** - Backend-specific documentation
- **[Security Guide](docs/security.md)** - Security best practices
- **[API Reference](docs/api.md)** - Developer API documentation
- **[Deployment Guide](docs/deployment.md)** - Production deployment

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

**n0n** - Enterprise-grade secure file sharing with multi-cloud storage, advanced encryption, and comprehensive management tools.