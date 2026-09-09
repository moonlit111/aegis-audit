//! Ownership proofs for recovering static work after a Windows desktop launcher exits.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, HANDLE},
    System::{
        JobObjects::*, Registry::*, SystemServices::JOB_OBJECT_QUERY, Threading::GetCurrentProcess,
    },
};

struct Job(HANDLE);
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn name_wide(name: &str) -> Result<Vec<u16>> {
    ensure!(
        name.starts_with("Global\\AegisAudit-") && name.len() <= 200 && !name.contains('\0'),
        "invalid desktop job name"
    );
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

fn open(name: &str) -> Result<Option<Job>> {
    let name = name_wide(name)?;
    let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, name.as_ptr()) };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(None);
        }
        return Err(error).context("query desktop job ownership");
    }
    Ok(Some(Job(handle)))
}

fn check_limits(job: &Job) -> Result<()> {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } != 0,
        "cannot verify desktop job limits"
    );
    ensure!(
        info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
        "desktop job does not guarantee kill-on-close"
    );
    Ok(())
}

fn verify_current_membership(name: &str) -> Result<()> {
    let job = open(name)?.context("desktop owner job does not exist")?;
    check_limits(&job)?;
    let mut member = 0;
    ensure!(
        unsafe { IsProcessInJob(GetCurrentProcess(), job.0, &mut member) } != 0 && member != 0,
        "executor is not a member of the declared desktop job"
    );
    Ok(())
}

fn machine_identity() -> Result<String> {
    let key: Vec<_> = "SOFTWARE\\Microsoft\\Cryptography"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let value: Vec<_> = "MachineGuid".encode_utf16().chain(Some(0)).collect();
    let mut buffer = [0u16; 128];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    ensure!(
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0,
        "cannot read the Windows machine identity"
    );
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .context("invalid Windows machine identity")?;
    let identity = String::from_utf16(&buffer[..end])?;
    ensure!(!identity.is_empty(), "empty Windows machine identity");
    Ok(aegis_domain::sha256(identity.as_bytes()))
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DesktopJob {
    pub name: String,
    pub machine_identity: String,
}

pub fn current_desktop_job() -> Result<Option<DesktopJob>> {
    let Some(name) = std::env::var_os("AEGIS_DESKTOP_JOB") else {
        return Ok(None);
    };
    let name = name
        .into_string()
        .map_err(|_| anyhow::anyhow!("invalid desktop job encoding"))?;
    verify_current_membership(&name)?;
    Ok(Some(DesktopJob {
        name,
        machine_identity: machine_identity()?,
    }))
}

#[derive(Serialize)]
pub struct ReapingProof {
    pub job_name: String,
    pub state: &'static str,
    pub active_processes: u32,
}

pub fn reaping_proof(owner: &DesktopJob) -> Result<Option<ReapingProof>> {
    ensure!(
        owner.machine_identity == machine_identity()?,
        "previous work belongs to a different Windows machine; cannot confirm its processes exited"
    );
    let name = &owner.name;
    let Some(job) = open(name)? else {
        return Ok(Some(ReapingProof {
            job_name: name.clone(),
            state: "CLOSED",
            active_processes: 0,
        }));
    };
    check_limits(&job)?;
    let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } != 0,
        "cannot verify previous desktop job process count"
    );
    Ok((info.ActiveProcesses == 0).then(|| ReapingProof {
        job_name: name.clone(),
        state: "EMPTY",
        active_processes: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::io::AsRawHandle,
        process::{Command, Stdio},
    };

    #[test]
    fn an_active_job_cannot_be_used_as_a_reaping_proof() {
        let name = format!("Global\\AegisAudit-test-{}", aegis_domain::id());
        let owner = DesktopJob {
            name: name.clone(),
            machine_identity: machine_identity().unwrap(),
        };
        let wide = name_wide(&name).unwrap();
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), wide.as_ptr()) };
        assert!(!handle.is_null());
        let job = Job(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            },
            0
        );
        assert_eq!(reaping_proof(&owner).unwrap().unwrap().state, "EMPTY");
        assert!(verify_current_membership(&name).is_err());
        let mut child = Command::new("ping.exe")
            .args(["-n", "20", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_ne!(
            unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle().cast()) },
            0
        );
        assert!(reaping_proof(&owner).unwrap().is_none());
        drop(job);
        child.wait().unwrap();
        assert!(reaping_proof(&owner).unwrap().is_some());
        assert!(
            reaping_proof(&DesktopJob {
                name: "an-unrelated-job".into(),
                ..owner.clone()
            })
            .is_err()
        );
        assert!(
            reaping_proof(&DesktopJob {
                machine_identity: "another-machine".into(),
                ..owner
            })
            .is_err()
        );
    }
}
