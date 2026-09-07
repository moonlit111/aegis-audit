use aegis_domain::{Exclusion, FileRecord, sha256};
use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

#[derive(Debug, Clone, Copy)]
pub struct ImportLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_file_bytes: 32 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct SourceBundle {
    pub files: Vec<FileRecord>,
    pub exclusions: Vec<Exclusion>,
    pub metadata: Value,
}

pub fn relative_path(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty() && raw.len() <= 4096,
        "empty or oversized path"
    );
    let path = raw.replace('\\', "/");
    ensure!(
        !path.starts_with('/'),
        "absolute archive path rejected: {raw}"
    );
    let path = path.trim_end_matches('/');
    ensure!(!path.is_empty(), "empty archive path");
    for component in path.split('/') {
        ensure!(
            !component.is_empty() && component != "." && component != "..",
            "path traversal or ambiguous path rejected: {raw}"
        );
        ensure!(
            !component.ends_with(' ') && !component.ends_with('.'),
            "path is not portable to Windows: {raw}"
        );
        ensure!(
            !component
                .chars()
                .any(|c| c.is_control() || "<>:\"|?*".contains(c)),
            "invalid path character: {raw}"
        );
        let base = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&base.as_str())
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && base.as_bytes()[3].is_ascii_digit()
                && base.as_bytes()[3] != b'0');
        ensure!(!reserved, "reserved Windows filename: {raw}");
    }
    Ok(path.to_owned())
}

pub fn portable_path_key(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

#[derive(Default)]
struct PathRegistry(HashMap<String, (String, bool)>);
impl PathRegistry {
    fn record(&mut self, path: &str, directory: bool) -> Result<()> {
        let parts: Vec<_> = path.split('/').collect();
        for index in 0..parts.len() {
            let prefix = parts[..=index].join("/");
            let is_dir = directory || index + 1 < parts.len();
            let key = portable_path_key(&prefix);
            if let Some((previous, previous_dir)) = self.0.get(&key) {
                ensure!(
                    previous == &prefix && *previous_dir && is_dir,
                    "duplicate, normalization/case-conflicting or file/directory path: {path}"
                );
            } else {
                self.0.insert(key, (prefix, is_dir));
            }
        }
        Ok(())
    }
}

pub fn language(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "py" | "pyi" => "python",
        "go" => "go",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => "cpp",
        "js" | "jsx" | "ts" | "tsx" | "java" | "rs" | "php" | "rb" | "cs" | "swift" | "kt"
        | "sh" | "bash" | "zsh" | "ps1" | "bat" | "cmd" | "lua" | "r" | "sql" | "scala" | "pl"
        | "pm" | "m" | "mm" | "vue" | "svelte" | "ipynb" => "unsupported",
        _ => "data",
    }
}

fn excluded(path: &str) -> Option<&'static str> {
    if path.split('/').any(|x| {
        [
            ".git",
            "node_modules",
            "target",
            ".venv",
            "venv",
            "__pycache__",
            ".cache",
            "build",
            "dist",
        ]
        .contains(&x)
    }) {
        return Some("版本库元数据、依赖缓存或构建目录，未纳入结构分析");
    }
    if Path::new(path)
        .file_name()
        .and_then(|x| x.to_str())
        .is_some_and(|n| n == ".env" || (n.starts_with(".env.") && n != ".env.example"))
    {
        return Some("本地环境配置，未纳入结构分析");
    }
    None
}

pub fn unpack_source(
    archive: &Path,
    destination: &Path,
    limits: ImportLimits,
) -> Result<SourceBundle> {
    let mut zip = ZipArchive::new(fs::File::open(archive)?).context("invalid ZIP archive")?;
    ensure!(
        zip.len() <= limits.max_files,
        "archive entry count exceeds {}",
        limits.max_files
    );
    fs::create_dir_all(destination)?;
    let mut seen = PathRegistry::default();
    let mut total = 0u64;
    let mut files = vec![];
    let mut exclusions = vec![];
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let path = relative_path(entry.name())?;
        let mode = entry.unix_mode().unwrap_or(0);
        ensure!(
            mode & 0o170000 != 0o120000,
            "symbolic link rejected: {path}"
        );
        seen.record(&path, entry.is_dir())?;
        if entry.is_dir() {
            continue;
        }
        ensure!(
            mode & 0o170000 == 0 || mode & 0o170000 == 0o100000,
            "non-regular ZIP entry rejected: {path}"
        );
        if let Some(reason) = excluded(&path) {
            exclusions.push(Exclusion {
                path,
                reason: reason.into(),
            });
            continue;
        }
        ensure!(
            entry.size() <= limits.max_file_bytes,
            "file exceeds import limit: {path}"
        );
        total = total
            .checked_add(entry.size())
            .context("archive size overflow")?;
        ensure!(
            total <= limits.max_total_bytes,
            "uncompressed archive exceeds import limit"
        );
        let mut bytes = vec![];
        (&mut entry)
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limits.max_file_bytes && bytes.len() as u64 == entry.size(),
            "archive size mismatch: {path}"
        );
        let target = destination.join(&path);
        fs::create_dir_all(target.parent().context("missing parent")?)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        output.write_all(&bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 }),
            )?;
        }
        files.push(FileRecord {
            path: path.clone(),
            sha256: sha256(&bytes),
            size: bytes.len() as u64,
            language: language(&path).into(),
        });
    }
    ensure!(!files.is_empty(), "archive contains no in-scope files");
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let metadata = detect_build_hints(&files);
    Ok(SourceBundle {
        files,
        exclusions,
        metadata,
    })
}

pub fn pack_directory(
    directory: &Path,
    output: &Path,
    limits: ImportLimits,
) -> Result<SourceBundle> {
    let mut paths: Vec<PathBuf> = vec![];
    let mut exclusions = vec![];
    let mut entries = walkdir::WalkDir::new(directory)
        .follow_links(false)
        .into_iter();
    let mut visited = 0usize;
    while let Some(entry) = entries.next() {
        let entry = entry?;
        if entry.path() == directory {
            continue;
        }
        visited += 1;
        ensure!(
            visited <= limits.max_files,
            "directory entry count exceeds limit"
        );
        let raw = entry
            .path()
            .strip_prefix(directory)?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(reason) = excluded(&raw) {
            if entry.file_type().is_dir() {
                entries.skip_current_dir();
            }
            exclusions.push(Exclusion {
                path: raw,
                reason: reason.into(),
            });
            continue;
        }
        ensure!(
            !entry.file_type().is_symlink(),
            "symbolic link rejected: {raw}"
        );
        if entry.file_type().is_file() {
            paths.push(entry.path().to_owned());
        }
    }
    paths.sort();
    ensure!(
        !paths.is_empty() && paths.len() <= limits.max_files,
        "empty directory or file count exceeds limit"
    );
    let mut writer = ZipWriter::new(fs::File::create(output)?);
    let mut files = vec![];
    let mut seen = PathRegistry::default();
    let mut total = 0u64;
    for path in paths {
        let relative = relative_path(&path.strip_prefix(directory)?.to_string_lossy())?;
        seen.record(&relative, false)?;
        let size = fs::metadata(&path)?.len();
        ensure!(
            size <= limits.max_file_bytes,
            "file exceeds import limit: {relative}"
        );
        total += size;
        ensure!(
            total <= limits.max_total_bytes,
            "directory exceeds import limit"
        );
        let data = fs::read(&path)?;
        ensure!(
            data.len() as u64 == size,
            "file changed during snapshot packing: {relative}"
        );
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&path)?.permissions().mode() & 0o111 != 0 {
                0o755
            } else {
                0o644
            }
        };
        #[cfg(not(unix))]
        let permissions = 0o644;
        writer.start_file(
            &relative,
            SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(permissions),
        )?;
        writer.write_all(&data)?;
        files.push(FileRecord {
            language: language(&relative).into(),
            path: relative,
            sha256: sha256(&data),
            size,
        });
    }
    writer.finish()?;
    Ok(SourceBundle {
        metadata: detect_build_hints(&files),
        files,
        exclusions,
    })
}

fn detect_build_hints(files: &[FileRecord]) -> Value {
    let mut hints = vec![];
    for file in files {
        let name = Path::new(&file.path)
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("");
        let tool = match name {
            "pyproject.toml" => "Python 项目配置",
            "requirements.txt" => "Python 依赖清单",
            "go.mod" => "Go module",
            "CMakeLists.txt" => "CMake",
            "Makefile" => "Make",
            _ => continue,
        };
        hints.push(json!({"path": file.path, "type": tool}));
    }
    json!({"build_hints": hints, "build_executed": false, "run_configuration_status": "NOT_REQUIRED_FOR_STRUCTURE_ANALYSIS"})
}

pub fn inspect_binary(bytes: &[u8]) -> Result<Value> {
    let format = if bytes.starts_with(b"MZ") {
        "PE"
    } else if bytes.starts_with(b"\x7fELF") {
        "ELF"
    } else {
        bail!("unsupported binary format: expected PE or ELF")
    };
    let file = object::File::parse(bytes).context("malformed PE/ELF file")?;
    let architecture = match file.architecture() {
        object::Architecture::I386 if format == "PE" => "x86",
        object::Architecture::X86_64 => "x86_64",
        _ => bail!("unsupported target architecture: {:?}", file.architecture()),
    };
    let sections: Vec<Value> = file.sections().take(256).map(|s| json!({"name":s.name().unwrap_or("<invalid>"),"address":format!("0x{:x}",s.address()),"size":s.size()})).collect();
    let protection_hints: Vec<&str> = if sections
        .iter()
        .any(|s| s["name"].as_str().is_some_and(|n| n.starts_with("UPX")))
    {
        vec!["UPX 节区特征；仅为识别线索，本轮未执行去壳"]
    } else {
        vec![]
    };
    Ok(
        json!({"format":format,"architecture":architecture,"entry":format!("0x{:x}",file.entry()),"sections":sections,"protection_hints":protection_hints,"target_executed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut zip = ZipWriter::new(f.reopen().unwrap());
        for (name, data) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        f
    }
    #[test]
    fn rejects_cross_platform_path_escapes() {
        for path in [
            "../secret",
            "/tmp/a",
            "C:\\a.py",
            "a/../../b",
            "a/CON.txt",
            "a./f",
            "a//f",
        ] {
            assert!(relative_path(path).is_err(), "{path}");
        }
        assert_eq!(relative_path("源码/处理.py").unwrap(), "源码/处理.py");
    }
    #[test]
    fn archive_limits_and_case_collisions_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let zip = archive(&[("a.py", b"123456")]);
        assert!(
            unpack_source(
                zip.path(),
                dir.path(),
                ImportLimits {
                    max_file_bytes: 5,
                    ..Default::default()
                }
            )
            .is_err()
        );
        let zip = archive(&[("Case.py", b"a"), ("case.py", b"b")]);
        assert!(unpack_source(zip.path(), dir.path(), ImportLimits::default()).is_err());
        for paths in [
            ["é.py", "e\u{301}.py"],
            ["Upper/a.py", "upper/b.py"],
            ["file.py", "file.py/child.py"],
        ] {
            let zip = archive(&[(paths[0], b"a"), (paths[1], b"b")]);
            let target = tempfile::tempdir().unwrap();
            assert!(unpack_source(zip.path(), target.path(), ImportLimits::default()).is_err());
        }
    }
    #[test]
    fn records_hashes_and_exclusions_without_extracting_git_history() {
        let zip = archive(&[
            ("代码/main.py", b"def hello():\n return 1\n"),
            (".git/config", b"private"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let result = unpack_source(zip.path(), dir.path(), ImportLimits::default()).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.exclusions.len(), 1);
        assert!(!dir.path().join(".git/config").exists());
        assert_eq!(result.files[0].sha256, sha256(b"def hello():\n return 1\n"));
    }
}
