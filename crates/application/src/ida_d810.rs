//! Optional IDA/Hex-Rays adapter. An actual local probe is required before advertising availability.
use crate::process::ProcessSpec;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct D810 {
    pub executable: PathBuf,
    pub plugin_root: PathBuf,
    pub dependencies: PathBuf,
    pub variant: String,
    pub executable_sha256: String,
    pub manager_sha256: String,
    pub bridge_sha256: String,
    pub ida_version: String,
    pub hexrays_version: String,
    pub verified: bool,
}

impl D810 {
    pub fn discover(bridge: &Path) -> Result<Self> {
        let path = std::env::var_os("AEGIS_IDA_D810_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".tools/ida-d810.json"));
        let settings: Self = serde_json::from_slice(
            &std::fs::read(path)
                .context("未配置 IDA/Hex-Rays + D-810；使用 scripts/configure_d810.py 探测")?,
        )?;
        ensure!(settings.verified, "IDA/D-810 尚未通过本机批处理探测");
        let name = settings
            .executable
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        ensure!(
            ["idat.exe", "idat64.exe"].contains(&name.as_str()),
            "必须配置 IDA 的控制台入口 idat.exe 或 idat64.exe"
        );
        ensure!(
            aegis_domain::sha256(&std::fs::read(&settings.executable)?)
                == settings.executable_sha256
                && aegis_domain::sha256(&std::fs::read(
                    settings.plugin_root.join("d810/manager.py")
                )?) == settings.manager_sha256
                && aegis_domain::sha256(&std::fs::read(bridge)?) == settings.bridge_sha256,
            "IDA、D-810 或桥接脚本变化后必须重新探测"
        );
        Ok(settings)
    }

    pub fn spec(&self, bridge: &Path, input: &Path, work: &Path) -> Result<ProcessSpec> {
        // IDA parses -S itself. Stage fixed relative names, avoiding nested quoting of user paths.
        std::fs::copy(bridge, work.join("d810_export.py"))?;
        ensure!(
            input == work.join("target.bin"),
            "IDA 输入必须是执行器暂存的固定文件名"
        );
        Ok(ProcessSpec {
            program: self.executable.clone(),
            args: vec![
                "-A".into(),
                "-Lida.log".into(),
                "-Sd810_export.py".into(),
                "-oanalysis.i64".into(),
                "target.bin".into(),
            ],
            directory: work.into(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(240),
        })
    }
}
