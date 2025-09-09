use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use sqlx::{PgPool, Row, Error as SqlxError};
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, PostgreSQLConfig, StorageError};

/// PostgreSQL storage backend
/// Stores chunks and metadata in a PostgreSQL database with ACID guarantees
pub struct PostgreSQLBackend {
    pool: PgPool,
    config: PostgreSQLConfig,
    table_prefix: String,
}

impl PostgreSQLBackend {
    pub async fn new(config: PostgreSQLConfig) -> Result<Self> {
        // Validate configuration
        if config.connection_string.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "PostgreSQL connection string cannot be empty".to_string(),
            }.into());
        }
        
        // Create connection pool
        let pool_size = config.pool_size.unwrap_or(10);
        let pool = PgPool::connect_with(
            config.connection_string.parse()
                .map_err(|e| StorageError::ConfigurationError {
                    message: format!("Invalid PostgreSQL connection string: {}", e),
                })?
        )
        .await
        .map_err(|e| StorageError::ConnectionError {
            message: format!("Failed to connect to PostgreSQL: {}", e),
        })?;
        
        let table_prefix = config.table_prefix.clone().unwrap_or_else(|| "n0n".to_string());
        
        let backend = Self {
            pool,
            config,
            table_prefix,
        };
        
        // Initialize database schema
        backend.init_schema().await?;
        
        Ok(backend)
    }
    
    /// Initialize database schema if it doesn't exist
    async fn init_schema(&self) -> Result<()> {
        let chunks_table = format!("{}_chunks", self.table_prefix);
        let metadata_table = format!("{}_metadata", self.table_prefix);
        
        // Create chunks table
        let chunks_sql = format!(r#"
            CREATE TABLE IF NOT EXISTS {} (
                id BIGSERIAL PRIMARY KEY,
                recipient VARCHAR(255) NOT NULL,
                chunk_hash VARCHAR(64) NOT NULL,
                data BYTEA NOT NULL,
                size BIGINT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(recipient, chunk_hash)
            )
        "#, chunks_table);
        
        // Create metadata table
        let metadata_sql = format!(r#"
            CREATE TABLE IF NOT EXISTS {} (
                id BIGSERIAL PRIMARY KEY,
                recipient VARCHAR(255) NOT NULL,
                chunk_hash VARCHAR(64) NOT NULL,
                nonce TEXT NOT NULL,
                sender_public_key TEXT NOT NULL,
                size BIGINT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(recipient, chunk_hash)
            )
        "#, metadata_table);
        
        // Create indexes for better performance
        let chunk_index_sql = format!(r#"
            CREATE INDEX IF NOT EXISTS idx_{}_chunks_recipient_hash 
            ON {} (recipient, chunk_hash)
        "#, self.table_prefix, chunks_table);
        
        let metadata_index_sql = format!(r#"
            CREATE INDEX IF NOT EXISTS idx_{}_metadata_recipient_hash 
            ON {} (recipient, chunk_hash)
        "#, self.table_prefix, metadata_table);
        
        let recipient_index_sql = format!(r#"
            CREATE INDEX IF NOT EXISTS idx_{}_chunks_recipient 
            ON {} (recipient)
        "#, self.table_prefix, chunks_table);
        
        // Execute schema creation
        sqlx::query(&chunks_sql).execute(&self.pool).await?;
        sqlx::query(&metadata_sql).execute(&self.pool).await?;
        sqlx::query(&chunk_index_sql).execute(&self.pool).await?;
        sqlx::query(&metadata_index_sql).execute(&self.pool).await?;
        sqlx::query(&recipient_index_sql).execute(&self.pool).await?;
        
        Ok(())
    }
    
    fn get_chunks_table(&self) -> String {
        format!("{}_chunks", self.table_prefix)
    }
    
    fn get_metadata_table(&self) -> String {
        format!("{}_metadata", self.table_prefix)
    }
    
    fn map_sqlx_error(err: SqlxError) -> StorageError {
        match err {
            SqlxError::RowNotFound => StorageError::ChunkNotFound {
                chunk_hash: "unknown".to_string(),
            },
            SqlxError::Database(db_err) => {
                if db_err.is_unique_violation() {
                    StorageError::BackendError {
                        message: "Chunk already exists".to_string(),
                    }
                } else {
                    StorageError::BackendError {
                        message: format!("Database error: {}", db_err),
                    }
                }
            }
            _ => StorageError::BackendError {
                message: format!("PostgreSQL operation failed: {}", err),
            },
        }
    }
}

#[async_trait]
impl StorageBackend for PostgreSQLBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let chunks_table = self.get_chunks_table();
        let sql = format!(r#"
            INSERT INTO {} (recipient, chunk_hash, data, size)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (recipient, chunk_hash) 
            DO UPDATE SET 
                data = EXCLUDED.data,
                size = EXCLUDED.size,
                updated_at = NOW()
        "#, chunks_table);
        
        match sqlx::query(&sql)
            .bind(recipient)
            .bind(chunk_hash)
            .bind(data)
            .bind(data.len() as i64)
            .execute(&self.pool)
            .await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => Err(Self::map_sqlx_error(e).into()),
        }
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let metadata_table = self.get_metadata_table();
        let sql = format!(r#"
            INSERT INTO {} (recipient, chunk_hash, nonce, sender_public_key, size, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (recipient, chunk_hash) 
            DO UPDATE SET 
                nonce = EXCLUDED.nonce,
                sender_public_key = EXCLUDED.sender_public_key,
                size = EXCLUDED.size,
                updated_at = NOW()
        "#, metadata_table);
        
        match sqlx::query(&sql)
            .bind(recipient)
            .bind(chunk_hash)
            .bind(&metadata.nonce)
            .bind(&metadata.sender_public_key)
            .bind(metadata.size as i64)
            .bind(metadata.created_at)
            .execute(&self.pool)
            .await {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_sqlx_error(e).into()),
        }
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let chunks_table = self.get_chunks_table();
        let sql = format!(r#"
            SELECT data FROM {} 
            WHERE recipient = $1 AND chunk_hash = $2
        "#, chunks_table);
        
        match sqlx::query(&sql)
            .bind(recipient)
            .bind(chunk_hash)
            .fetch_one(&self.pool)
            .await {
            Ok(row) => {
                let data: Vec<u8> = row.get("data");
                Ok(data)
            },
            Err(SqlxError::RowNotFound) => Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
            Err(e) => Err(Self::map_sqlx_error(e).into()),
        }
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let metadata_table = self.get_metadata_table();
        let sql = format!(r#"
            SELECT nonce, sender_public_key, size, created_at 
            FROM {} 
            WHERE recipient = $1 AND chunk_hash = $2
        "#, metadata_table);
        
        match sqlx::query(&sql)
            .bind(recipient)
            .bind(chunk_hash)
            .fetch_one(&self.pool)
            .await {
            Ok(row) => {
                Ok(ChunkMetadata {
                    nonce: row.get("nonce"),
                    sender_public_key: row.get("sender_public_key"),
                    size: row.get::<i64, _>("size") as u64,
                    created_at: row.get("created_at"),
                })
            },
            Err(SqlxError::RowNotFound) => Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
            Err(e) => Err(Self::map_sqlx_error(e).into()),
        }
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let chunks_table = self.get_chunks_table();
        let sql = format!(r#"
            SELECT chunk_hash FROM {} 
            WHERE recipient = $1 
            ORDER BY created_at ASC
        "#, chunks_table);
        
        match sqlx::query(&sql)
            .bind(recipient)
            .fetch_all(&self.pool)
            .await {
            Ok(rows) => {
                let chunks: Vec<String> = rows.iter()
                    .map(|row| row.get("chunk_hash"))
                    .collect();
                Ok(chunks)
            },
            Err(e) => Err(Self::map_sqlx_error(e).into()),
        }
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunks_table = self.get_chunks_table();
        let metadata_table = self.get_metadata_table();
        
        // Use a transaction to ensure both deletions succeed or fail together
        let mut tx = self.pool.begin().await?;
        
        // Delete chunk data
        let chunk_sql = format!("DELETE FROM {} WHERE recipient = $1 AND chunk_hash = $2", chunks_table);
        sqlx::query(&chunk_sql)
            .bind(recipient)
            .bind(chunk_hash)
            .execute(&mut *tx)
            .await?;
        
        // Delete metadata
        let metadata_sql = format!("DELETE FROM {} WHERE recipient = $1 AND chunk_hash = $2", metadata_table);
        sqlx::query(&metadata_sql)
            .bind(recipient)
            .bind(chunk_hash)
            .execute(&mut *tx)
            .await?;
        
        // Commit transaction
        tx.commit().await?;
        
        Ok(())
    }
    
    async fn test_connection(&self) -> Result<()> {
        // Test connection by running a simple query
        match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("PostgreSQL connection test failed: {}", e),
            }.into()),
        }
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::PostgreSQL
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "PostgreSQL".to_string());
        info.insert("table_prefix".to_string(), self.table_prefix.clone());
        
        // Extract database info from connection string (safely)
        let conn_str = &self.config.connection_string;
        if let Ok(parsed) = conn_str.parse::<url::Url>() {
            if let Some(host) = parsed.host_str() {
                info.insert("host".to_string(), host.to_string());
            }
            if let Some(port) = parsed.port() {
                info.insert("port".to_string(), port.to_string());
            }
            if !parsed.path().is_empty() && parsed.path() != "/" {
                info.insert("database".to_string(), parsed.path().trim_start_matches('/').to_string());
            }
            if !parsed.username().is_empty() {
                info.insert("username".to_string(), parsed.username().to_string());
            }
        }
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("connection".to_string(), "ok".to_string());
                
                // Get database version and other info
                if let Ok(row) = sqlx::query("SELECT version()").fetch_one(&self.pool).await {
                    let version: String = row.get(0);
                    health.insert("postgres_version".to_string(), version);
                }
                
                // Check table existence
                let chunks_table = self.get_chunks_table();
                let table_check_sql = r#"
                    SELECT COUNT(*) as count FROM information_schema.tables 
                    WHERE table_name = $1
                "#;
                
                if let Ok(row) = sqlx::query(table_check_sql).bind(&chunks_table).fetch_one(&self.pool).await {
                    let count: i64 = row.get("count");
                    health.insert("schema_initialized".to_string(), (count > 0).to_string());
                }
                
                // Get pool statistics
                health.insert("pool_size".to_string(), self.pool.size().to_string());
                health.insert("pool_idle".to_string(), self.pool.num_idle().to_string());
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }
        
        Ok(health)
    }
    
    /// Batch operations are naturally efficient in PostgreSQL with prepared statements
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        
        // Use a transaction for the entire batch
        let mut tx = self.pool.begin().await?;
        let mut results = Vec::new();
        
        let chunks_table = self.get_chunks_table();
        let metadata_table = self.get_metadata_table();
        
        // Prepare statements for better performance
        let chunk_sql = format!(r#"
            INSERT INTO {} (recipient, chunk_hash, data, size)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (recipient, chunk_hash) 
            DO UPDATE SET 
                data = EXCLUDED.data,
                size = EXCLUDED.size,
                updated_at = NOW()
        "#, chunks_table);
        
        let metadata_sql = format!(r#"
            INSERT INTO {} (recipient, chunk_hash, nonce, sender_public_key, size, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (recipient, chunk_hash) 
            DO UPDATE SET 
                nonce = EXCLUDED.nonce,
                sender_public_key = EXCLUDED.sender_public_key,
                size = EXCLUDED.size,
                updated_at = NOW()
        "#, metadata_table);
        
        for (hash, data, metadata) in chunks {
            // Insert chunk
            sqlx::query(&chunk_sql)
                .bind(recipient)
                .bind(&hash)
                .bind(&data)
                .bind(data.len() as i64)
                .execute(&mut *tx)
                .await?;
            
            // Insert metadata
            sqlx::query(&metadata_sql)
                .bind(recipient)
                .bind(&hash)
                .bind(&metadata.nonce)
                .bind(&metadata.sender_public_key)
                .bind(metadata.size as i64)
                .bind(metadata.created_at)
                .execute(&mut *tx)
                .await?;
            
            results.push(hash);
        }
        
        // Commit the entire batch
        tx.commit().await?;
        
        Ok(results)
    }
}

// Add URL parsing dependency to Cargo.toml if not already present
// url = "2.5"