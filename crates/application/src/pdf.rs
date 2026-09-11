//! Print the escaped, self-contained report with an isolated local browser.
//! No operator profile, model credentials, remote page, or global write lock is used.
use crate::process::{ProcessSpec, run};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

static PRINT_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub fn browser_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("AEGIS_PDF_BROWSER") {
        let path = PathBuf::from(path);
        return (path.is_absolute()
            && path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe")))
        .then_some(path);
    }
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .iter()
        .filter_map(std::env::var_os)
        .flat_map(|root| {
            [
                PathBuf::from(&root).join("Microsoft/Edge/Application/msedge.exe"),
                PathBuf::from(root).join("Google/Chrome/Application/chrome.exe"),
            ]
        })
        .find(|path| path.is_file())
}

pub async fn render(html: &[u8]) -> Result<Vec<u8>> {
    let _slot = PRINT_SLOTS
        .try_acquire()
        .context("已有两个 PDF 正在生成，请稍后重试")?;
    let browser = browser_path().context(
        "PDF 导出需要本机 Microsoft Edge 或 Chrome；可通过 AEGIS_PDF_BROWSER 指定浏览器可执行文件",
    )?;
    let temp = tempfile::Builder::new().prefix("aegis-pdf-").tempdir()?;
    let input = temp.path().join("report.html");
    let output = temp.path().join("report.pdf");
    tokio::fs::write(&input, html).await?;
    let url = reqwest::Url::from_file_path(&input)
        .map_err(|_| anyhow::anyhow!("PDF 临时文件路径无效"))?;
    let result = run(
        ProcessSpec {
            program: browser,
            args: vec![
                "--headless=new".into(),
                "--disable-gpu".into(),
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                "--disable-extensions".into(),
                "--disable-sync".into(),
                "--disable-background-networking".into(),
                "--disable-component-update".into(),
                "--no-pdf-header-footer".into(),
                "--virtual-time-budget=1000".into(),
                format!("--user-data-dir={}", temp.path().join("profile").display()),
                format!("--print-to-pdf={}", output.display()),
                url.to_string(),
            ],
            directory: temp.path().into(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(45),
        },
        CancellationToken::new(),
        |_| {},
    )
    .await
    .context("本地 PDF 排版进程启动失败")?;
    ensure!(
        !result.timed_out
            && !result.cancelled
            && result.processes_reaped
            && result.exit_code == Some(0),
        "PDF 排版未正常完成；未保存不完整报告，请重试或使用 HTML 导出"
    );
    let size = tokio::fs::metadata(&output)
        .await
        .context("排版进程未生成 PDF")?
        .len();
    ensure!(
        (1024..=64 * 1024 * 1024).contains(&size),
        "PDF 文件大小无效或超过 64 MiB"
    );
    let bytes = tokio::fs::read(output).await?;
    ensure!(bytes.starts_with(b"%PDF-"), "排版结果不是有效 PDF");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires an installed local Edge or Chrome; never uses a remote site"]
    async fn local_browser_produces_real_pdf_and_reaps_its_processes() {
        let bytes = render("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\"><h1>中文报告验证</h1><p>原文证据、人工复核、阶段报告。</p></html>".as_bytes()).await.unwrap();
        assert!(bytes.starts_with(b"%PDF-"));
        if let Some(path) = std::env::var_os("AEGIS_PDF_EVIDENCE") {
            tokio::fs::write(path, bytes).await.unwrap();
        }
    }
}
