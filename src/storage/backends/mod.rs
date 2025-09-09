pub mod local;
pub mod sftp;
pub mod s3;
pub mod gcs;
pub mod postgresql;
pub mod redis;
pub mod multicloud;

pub use local::LocalBackend;
pub use sftp::SftpBackend;
pub use s3::S3Backend;
pub use gcs::GcsBackend;
pub use postgresql::PostgreSQLBackend;
pub use redis::RedisBackend;
pub use multicloud::MultiCloudBackend;