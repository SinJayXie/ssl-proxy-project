//! 服务抽象 + 注册表。
//!
//! 设计目标：
//! 1. 每个服务实现 [`Service`] 特征，提供 `name/start/stop`；
//! 2. [`ServiceRegister`] 按注册顺序构造并启动；
//! 3. 服务间通过构造函数注入显式依赖，避免全局状态。

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Service: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// 启动服务（绑定端口、初始化资源等）
    async fn start(&self) -> Result<()>;

    /// 优雅停止
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
}

/// 服务注册表
pub struct ServiceRegister {
    services: Vec<Arc<dyn Service>>,
}

impl ServiceRegister {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    pub fn add<S: Service>(mut self, svc: Arc<S>) -> Self {
        self.services.push(svc);
        self
    }

    /// 顺序启动所有服务
    pub async fn start_all(&self) -> Result<()> {
        let n = self.services.len();
        tracing::info!("Starting {} service(s)...", n);
        for svc in &self.services {
            tracing::info!("  -> start service [{}]", svc.name());
            svc.start().await?;
        }
        tracing::info!("All services started.");
        Ok(())
    }

    /// 逆序停止所有服务
    pub async fn stop_all(&self) -> Result<()> {
        for svc in self.services.iter().rev() {
            tracing::info!("  <- stop service [{}]", svc.name());
            if let Err(e) = svc.stop().await {
                tracing::warn!("stop service [{}] failed: {:#}", svc.name(), e);
            }
        }
        Ok(())
    }
}

impl Default for ServiceRegister {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockService {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        fail_stop: bool,
    }

    #[async_trait]
    impl Service for MockService {
        fn name(&self) -> &str {
            self.name
        }

        async fn start(&self) -> Result<()> {
            self.log.lock().unwrap().push(format!("start:{}", self.name));
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.log.lock().unwrap().push(format!("stop:{}", self.name));
            if self.fail_stop {
                anyhow::bail!("mock stop failure");
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn starts_in_registration_order_and_stops_in_reverse() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let register = ServiceRegister::new()
            .add(Arc::new(MockService {
                name: "a",
                log: log.clone(),
                fail_stop: false,
            }))
            .add(Arc::new(MockService {
                name: "b",
                log: log.clone(),
                fail_stop: false,
            }));

        register.start_all().await.unwrap();
        register.stop_all().await.unwrap();

        assert_eq!(
            *log.lock().unwrap(),
            vec!["start:a", "start:b", "stop:b", "stop:a"]
        );
    }

    #[tokio::test]
    async fn stop_all_continues_after_failure() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let register = ServiceRegister::new()
            .add(Arc::new(MockService {
                name: "a",
                log: log.clone(),
                fail_stop: false,
            }))
            .add(Arc::new(MockService {
                name: "b",
                log: log.clone(),
                fail_stop: true,
            }));

        register.start_all().await.unwrap();
        // 单个服务停止失败不应中断整体关闭流程
        assert!(register.stop_all().await.is_ok());

        let log = log.lock().unwrap().clone();
        assert_eq!(log, vec!["start:a", "start:b", "stop:b", "stop:a"]);
    }
}
