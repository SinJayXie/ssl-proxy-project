//! 统一错误类型

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("配置错误: {0}")]
    #[allow(dead_code)]
    Config(String),

    #[error("TLS 错误: {0}")]
    #[allow(dead_code)]
    Tls(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML 解析错误: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("认证失败")]
    #[allow(dead_code)]
    Auth,

    #[error("其他错误: {0}")]
    #[allow(dead_code)]
    Other(String),
}

#[allow(dead_code)]
pub type AppResult<T> = Result<T, AppError>;
