//! Disposable Docker execution. Killing the Docker client is not sufficient: always remove the owned container.
#[path = "windows_runtime.rs"]
pub mod windows_runtime;
#[path = "windows_sandbox.rs"]
pub mod windows_sandbox;

use crate::process::{self, ProcessOutput, ProcessSpec};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub const IMAGE: &str = "aegis-runtime:0.2.0";

pub async fn image_id() -> Option<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("docker")
            .args([
                "image",
                "inspect",
                "--format",
                "{{.Id}} {{.Architecture}}",
                IMAGE,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let value = String::from_utf8(output.stdout).ok()?;
    let (id, architecture) = value.trim().split_once(' ')?;
    (output.status.success()
        && id.starts_with("sha256:")
        && id.len() == 71
        && architecture == "amd64")
        .then(|| id.to_owned())
}
async fn docker(
    args: Vec<String>,
    directory: &Path,
    timeout: Duration,
    cancel: CancellationToken,
    progress: impl Fn(&str) + Send + Sync + 'static,
) -> Result<ProcessOutput> {
    process::run(
        ProcessSpec {
            program: "docker".into(),
            args,
            directory: directory.into(),
            env: BTreeMap::new(),
            timeout,
        },
        cancel,
        progress,
    )
    .await
}

pub struct ContainerSpec {
    pub image: String,
    pub work: PathBuf,
    pub target: PathBuf,
    pub runner: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
}
pub async fn run(
    spec: ContainerSpec,
    cancel: CancellationToken,
    progress: impl Fn(&str) + Send + Sync + 'static,
) -> Result<ProcessOutput> {
    let ContainerSpec {
        image,
        work,
        target,
        runner,
        args,
        timeout,
    } = spec;
    ensure!(
        image.starts_with("sha256:")
            && image.len() == 71
            && image[7..].bytes().all(|b| b.is_ascii_hexdigit()),
        "运行镜像必须固定到已检查的内容 ID"
    );
    let work = std::fs::canonicalize(work)?;
    let target = std::fs::canonicalize(target)?;
    let runner = std::fs::canonicalize(runner)?;
    let mounts = [
        (&work, "/input", true),
        (&target, "/target", true),
        (&runner, "/runner", true),
    ];
    let name = format!("aegis-{}", aegis_domain::id());
    let mut create = vec![
        "create".into(),
        "--name".into(),
        name.clone(),
        "--platform".into(),
        "linux/amd64".into(),
        "--init".into(),
        "--network".into(),
        "none".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        "128".into(),
        "--memory".into(),
        "1g".into(),
        "--cpus".into(),
        "1".into(),
        "--ulimit".into(),
        "core=0".into(),
        "--ulimit".into(),
        "fsize=134217728".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=256m".into(),
        "--tmpfs".into(),
        "/work:rw,exec,nosuid,nodev,size=512m,mode=1777".into(),
        "--user".into(),
        "65534:65534".into(),
        "--env".into(),
        "HOME=/tmp".into(),
        "--workdir".into(),
        "/work".into(),
    ];
    for (source, destination, read_only) in mounts {
        let source = source.to_string_lossy();
        ensure!(
            !source.contains([',', '\n', '\r']),
            "容器挂载路径包含不支持的字符"
        );
        create.extend([
            "--mount".into(),
            format!(
                "type=bind,src={source},dst={destination}{}",
                if read_only { ",readonly" } else { "" }
            ),
        ]);
    }
    create.push(image);
    create.extend(args);
    let created = docker(
        create,
        &work,
        Duration::from_secs(30),
        cancel.clone(),
        |_| {},
    )
    .await;
    let result = match created {
        Ok(created) if created.exit_code == Some(0) && !created.cancelled && !created.timed_out => {
            docker(
                vec!["start".into(), "--attach".into(), name.clone()],
                &work,
                timeout,
                cancel,
                progress,
            )
            .await
        }
        other => other,
    };
    // This cleanup has its own cancellation token; the target cannot retain a live container after cancellation.
    let cleanup = docker(
        vec!["rm".into(), "--force".into(), name.clone()],
        &work,
        Duration::from_secs(20),
        CancellationToken::new(),
        |_| {},
    )
    .await;
    let mut removed = cleanup.is_ok_and(|out| out.exit_code == Some(0) && out.processes_reaped);
    if !removed {
        let check = docker(
            vec!["container".into(), "inspect".into(), name],
            &work,
            Duration::from_secs(10),
            CancellationToken::new(),
            |_| {},
        )
        .await;
        removed = check.is_ok_and(|out| {
            out.exit_code == Some(1)
                && out.processes_reaped
                && String::from_utf8_lossy(&out.stderr).contains("No such container")
        });
    }
    let mut output = result?;
    output.processes_reaped &= removed;
    if !removed {
        output.stderr.extend_from_slice(
            b"\nContainer removal was not confirmed; executor must remain quarantined.\n",
        );
    }
    Ok(output)
}

pub fn prepare_work(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
