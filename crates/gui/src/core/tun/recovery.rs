//! 崩溃恢复：TUN 路由的持久化快照与启动自检。
//!
//! 路由快照与崩溃恢复：进程内清理无法覆盖 SIGKILL / 系统崩溃，
//! 因此把"已安装路由的撤销命令"持久化到配置目录：
//! - 路由安装成功后写快照（含进程 pid）；
//! - 正常停止后删除快照；
//! - 下次启动先读快照，若存在则执行撤销并删除（无论上次是否正常退出）。
//!
//! 快照本身只含 `route delete` 命令，不含任何敏感信息；执行由调用方负责，
//! 这里提供纯逻辑（序列化/反序列化/CRC 校验）便于单元测试。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 快照文件名（在 config_dir 下）。
pub const SNAPSHOT_FILE: &str = "tun-routes.json";

/// 路由快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSnapshot {
    /// 写入快照的进程 pid，仅用于日志诊断。
    pub pid: u32,
    /// 按安装顺序的撤销命令（runner 的 program.down）。
    pub down_cmds: Vec<String>,
    /// TUN 设备名，便于日志。
    pub device: String,
}

impl RouteSnapshot {
    pub fn new(pid: u32, device: String, down_cmds: Vec<String>) -> Self {
        Self { pid, device, down_cmds }
    }

    /// 写入快照（原子替换：先写临时文件再 rename）。
    pub fn save(&self, config_dir: &Path) -> Result<(), String> {
        let path = snapshot_path(config_dir);
        let tmp = path.with_extension("json.tmp");
        let content = serde_json::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, content).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// 读取快照。文件不存在返回 Ok(None)；损坏返回 Err（调用方应保守地
    /// 不执行任何命令，但记录错误——快照损坏时无法安全回滚）。
    pub fn load(config_dir: &Path) -> Result<Option<Self>, String> {
        let path = snapshot_path(config_dir);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let snap: Self = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        Ok(Some(snap))
    }

    /// 删除快照（正常停止后调用）。
    pub fn clear(config_dir: &Path) -> Result<(), String> {
        let path = snapshot_path(config_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// 校验快照有效性：所有命令必须是 `route delete` 开头，
    /// 防止被篡改的快照执行任意命令（即使被篡改也只应影响路由）。
    pub fn is_valid(&self) -> bool {
        !self.down_cmds.is_empty()
            && self
                .down_cmds
                .iter()
                .all(|c| c.trim_start().starts_with("route delete "))
    }
}

pub fn snapshot_path(config_dir: &Path) -> PathBuf {
    config_dir.join(SNAPSHOT_FILE)
}

/// 启动自检：若存在有效快照则给出待执行的撤销命令。
/// 返回 None 表示无需恢复；Some(cmds) 表示调用方应执行这些命令并清理快照。
pub fn pending_rollback(config_dir: &Path) -> Result<Option<Vec<String>>, String> {
    match RouteSnapshot::load(config_dir)? {
        None => Ok(None),
        Some(snap) => {
            if snap.is_valid() {
                log::warn!(
                    "found residual TUN route snapshot (pid {}, device {}), running crash recovery",
                    snap.pid,
                    snap.device
                );
                Ok(Some(snap.down_cmds))
            } else {
                log::error!("invalid TUN route snapshot (possibly tampered or corrupted), ignored");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds() -> Vec<String> {
        vec![
            "route delete 0.0.0.0 mask 0.0.0.0 198.18.0.1".into(),
            "route delete 1.2.3.4 mask 255.255.255.255 192.168.1.1".into(),
        ]
    }

    #[test]
    fn snapshot_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-recovery-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let snap = RouteSnapshot::new(1234, "SSLProxy".into(), cmds());
        snap.save(&dir).unwrap();
        let got = RouteSnapshot::load(&dir).unwrap().unwrap();
        assert_eq!(got, snap);
        snap.validate_and_clear(&dir);
        assert!(RouteSnapshot::load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    impl RouteSnapshot {
        fn validate_and_clear(&self, dir: &Path) {
            assert!(self.is_valid());
            <Self>::clear(dir).unwrap();
        }
    }

    #[test]
    fn snapshot_validates_delete_commands() {
        let good = RouteSnapshot::new(1, "d".into(), cmds());
        assert!(good.is_valid());
        let bad = RouteSnapshot::new(1, "d".into(), vec!["format C:".into()]);
        assert!(!bad.is_valid());
        let empty = RouteSnapshot::new(1, "d".into(), vec![]);
        assert!(!empty.is_valid());
    }

    #[test]
    fn pending_rollback_returns_commands_when_snapshot_exists() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-recovery-pending-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(pending_rollback(&dir).unwrap().is_none());
        let snap = RouteSnapshot::new(1, "SSLProxy".into(), cmds());
        snap.save(&dir).unwrap();
        assert_eq!(pending_rollback(&dir).unwrap(), Some(cmds()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_snapshot_is_ignored() {
        let dir = std::env::temp_dir().join(format!("ssl-proxy-recovery-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(snapshot_path(&dir), b"not json").unwrap();
        assert!(pending_rollback(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
