#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("AegisAudit supports Windows x64 only.");

pub mod audit;
pub mod credentials;
pub mod import;
pub mod model;
pub mod process;
pub mod protection;
pub mod report;
pub mod runtime;
pub mod sast;
pub mod source;
pub mod windows_job;
