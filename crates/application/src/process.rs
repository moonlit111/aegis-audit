use anyhow::{Context, Result};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub directory: PathBuf,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub cancelled: bool,
    pub timed_out: bool,
    pub processes_reaped: bool,
}

const LOG_LIMIT: usize = 4 * 1024 * 1024;

async fn drain(
    mut reader: impl AsyncRead + Unpin,
    name: &'static str,
    tx: mpsc::Sender<(&'static str, Vec<u8>)>,
) {
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.send((name, buffer[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(windows)]
struct ProcessGroup(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
unsafe impl Send for ProcessGroup {}
#[cfg(windows)]
impl ProcessGroup {
    fn new(child: &Child) -> Result<Self> {
        use windows_sys::Win32::System::JobObjects::*;
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            anyhow::ensure!(
                !handle.is_null(),
                "CreateJobObjectW: {}",
                std::io::Error::last_os_error()
            );
            let job = Self(handle);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            anyhow::ensure!(
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32
                ) != 0,
                "set job limits: {}",
                std::io::Error::last_os_error()
            );
            let process = child.raw_handle().context("child has no process handle")?;
            anyhow::ensure!(
                AssignProcessToJobObject(handle, process.cast()) != 0,
                "assign process to job: {}",
                std::io::Error::last_os_error()
            );
            // The child is suspended until the job owns it, so it cannot launch
            // a descendant in the interval before AssignProcessToJobObject.
            use windows_sys::Win32::{
                Foundation::*,
                System::{Diagnostics::ToolHelp::*, Threading::*},
            };
            let threads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            anyhow::ensure!(
                threads != INVALID_HANDLE_VALUE,
                "enumerate suspended child thread"
            );
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of_val(&entry) as u32;
            let mut found = Thread32First(threads, &mut entry) != 0;
            let mut resumed = false;
            while found {
                if Some(entry.th32OwnerProcessID) == child.id() {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !thread.is_null() {
                        resumed = ResumeThread(thread) != u32::MAX;
                        CloseHandle(thread);
                    }
                    break;
                }
                found = Thread32Next(threads, &mut entry) != 0;
            }
            CloseHandle(threads);
            anyhow::ensure!(resumed, "resume suspended child after job assignment");
            Ok(job)
        }
    }
    fn terminate(&self) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
    fn empty(&self) -> bool {
        use windows_sys::Win32::System::JobObjects::*;
        unsafe {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            QueryInformationJobObject(
                self.0,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            ) != 0
                && info.ActiveProcesses == 0
        }
    }
}
#[cfg(windows)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub async fn run(
    spec: ProcessSpec,
    cancel: CancellationToken,
    mut progress: impl FnMut(&str),
) -> Result<ProcessOutput> {
    #[cfg(windows)]
    if spec
        .program
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd"))
    {
        anyhow::ensure!(
            spec.args
                .iter()
                .chain(std::iter::once(
                    &spec.program.to_string_lossy().into_owned()
                ))
                .all(|arg| !arg.chars().any(|c| "%!&|<>^\r\n".contains(c))),
            "Windows batch tool paths contain unsupported shell metacharacters"
        );
    }
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();
    // Credentials from the control plane are deliberately not inherited by tools.
    for key in [
        "PATH",
        "JAVA_HOME",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // Do not put transient files in the target snapshot. Native tools such as
    // Semgrep also use AF_UNIX sockets under TEMP, with much shorter path limits.
    let temp = tempfile::Builder::new().prefix("aegis-tool-").tempdir()?;
    for name in ["TMPDIR", "TMP", "TEMP"] {
        command.env(name, temp.path());
    }
    #[cfg(windows)]
    {
        // Ghidra needs APPDATA; keep tool settings away from the user's profile.
        let profile = temp.path().join("profile");
        let roaming = profile.join("AppData/Roaming");
        let local = profile.join("AppData/Local");
        tokio::fs::create_dir_all(&roaming).await?;
        tokio::fs::create_dir_all(&local).await?;
        command
            .env("USERPROFILE", profile)
            .env("APPDATA", roaming)
            .env("LOCALAPPDATA", local);
    }
    command.envs(spec.env);
    #[cfg(windows)]
    {
        command.creation_flags(0x00000200 | 0x00000004);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("launch {}", spec.program.display()))?;
    let group = match ProcessGroup::new(&child) {
        Ok(group) => group,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error);
        }
    };
    let (tx, mut rx) = mpsc::channel(64);
    let stdout_reader = tokio::spawn(drain(
        child.stdout.take().context("missing stdout")?,
        "stdout",
        tx.clone(),
    ));
    let stderr_reader = tokio::spawn(drain(
        child.stderr.take().context("missing stderr")?,
        "stderr",
        tx,
    ));
    let mut output = ProcessOutput {
        exit_code: None,
        stdout: vec![],
        stderr: vec![],
        truncated: false,
        cancelled: false,
        timed_out: false,
        processes_reaped: false,
    };
    let deadline = tokio::time::sleep(spec.timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            status = child.wait() => { output.exit_code = status?.code(); break; }
            chunk = rx.recv() => if let Some((stream, data)) = chunk { append(&mut output, stream, &data, &mut progress); },
            _ = cancel.cancelled() => { output.cancelled = true; group.terminate(); output.exit_code = child.wait().await?.code(); break; }
            _ = &mut deadline => { output.timed_out = true; group.terminate(); output.exit_code = child.wait().await?.code(); break; }
        }
    }
    group.terminate();
    for _ in 0..100 {
        if group.empty() {
            output.processes_reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    while let Ok(Some((stream, data))) =
        tokio::time::timeout(Duration::from_secs(2), rx.recv()).await
    {
        append(&mut output, stream, &data, &mut progress);
    }
    stdout_reader.abort();
    stderr_reader.abort();
    let _ = stdout_reader.await;
    let _ = stderr_reader.await;
    Ok(output)
}

fn append(output: &mut ProcessOutput, stream: &str, data: &[u8], progress: &mut impl FnMut(&str)) {
    let target = if stream == "stdout" {
        &mut output.stdout
    } else {
        &mut output.stderr
    };
    let available = LOG_LIMIT.saturating_sub(target.len());
    target.extend_from_slice(&data[..available.min(data.len())]);
    if data.len() > available {
        output.truncated = true;
    }
    if available > 0 {
        progress(&format!("[{stream}] {}", String::from_utf8_lossy(data)));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[tokio::test]
    async fn tools_get_private_profile_directories() {
        let directory = tempfile::Builder::new()
            .prefix("aegis profile ")
            .tempdir()
            .unwrap();
        let script = directory.path().join("profile-check.cmd");
        std::fs::write(
            &script,
            concat!(
                "@echo off\r\n",
                "if not exist \"%APPDATA%\\.\" exit /b 9\r\n",
                "if not exist \"%LOCALAPPDATA%\\.\" exit /b 10\r\n",
                "if not exist \"%USERPROFILE%\\.\" exit /b 11\r\n",
                "echo %APPDATA%\r\necho %LOCALAPPDATA%\r\necho %USERPROFILE%\r\n"
            ),
        )
        .unwrap();
        let output = run(
            ProcessSpec {
                program: "cmd.exe".into(),
                args: vec![
                    "/D".into(),
                    "/U".into(),
                    "/C".into(),
                    script.to_string_lossy().into_owned(),
                ],
                directory: directory.path().to_owned(),
                env: BTreeMap::new(),
                timeout: Duration::from_secs(5),
            },
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(output.processes_reaped && !output.cancelled && !output.timed_out);
        let (words, remainder) = output.stdout.as_chunks::<2>();
        assert!(remainder.is_empty());
        let wide: Vec<_> = words.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        let stdout = String::from_utf16(&wide).unwrap();
        let paths: Vec<_> = stdout
            .lines()
            .map(|line| PathBuf::from(line.trim()))
            .collect();
        assert_eq!(paths.len(), 3);
        for path in paths {
            assert!(path.starts_with(std::env::temp_dir()), "{path:?}");
            assert!(!path.starts_with(directory.path()), "{path:?}");
            assert!(path.components().any(|part| {
                part.as_os_str()
                    .to_string_lossy()
                    .starts_with("aegis-tool-")
            }));
            assert!(!path.exists(), "temporary profile must be cleaned up");
        }
    }

    #[tokio::test]
    async fn timeout_reaps_windows_job_and_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let output = run(
            ProcessSpec {
                program: "cmd.exe".into(),
                args: vec![
                    "/D".into(),
                    "/C".into(),
                    "echo before & ping -n 10 127.0.0.1 > NUL".into(),
                ],
                directory: directory.path().to_owned(),
                env: BTreeMap::new(),
                timeout: Duration::from_millis(300),
            },
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();
        assert!(output.timed_out && output.processes_reaped);
        assert!(String::from_utf8_lossy(&output.stdout).contains("before"));
    }

    #[tokio::test]
    async fn cancellation_reaps_windows_job() {
        let directory = tempfile::tempdir().unwrap();
        let token = CancellationToken::new();
        let trigger = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            trigger.cancel();
        });
        let output = run(
            ProcessSpec {
                program: "ping.exe".into(),
                args: vec!["-n".into(), "10".into(), "127.0.0.1".into()],
                directory: directory.path().to_owned(),
                env: BTreeMap::new(),
                timeout: Duration::from_secs(15),
            },
            token,
            |_| {},
        )
        .await
        .unwrap();
        assert!(output.cancelled && output.processes_reaped && !output.timed_out);
    }
}
