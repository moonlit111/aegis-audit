//! B07 正常运行配置：从导入的目标树静态识别构建系统、入口、输入接口与依赖，
//! 产出可版本化的声明式配置。只读识别，不执行目标，不接受宿主任意命令；
//! 缺失项显式列出，配置缺失不阻断独立静态审计。
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// 识别上限：避免大仓库拖垮导入。
const MAX_FILES: usize = 20_000;
const MAX_FILE_BYTES: u64 = 512 * 1024;
const MAX_SAMPLE: usize = 8;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".pnpm-store",
];

const TEXT_SUFFIXES: &[&str] = &[
    "toml", "json", "txt", "cfg", "ini", "mod", "py", "rs", "go", "c", "cc", "cpp", "h", "hpp",
    "js", "ts", "tsx", "java", "rb", "sh", "yml", "yaml", "gradle", "xml", "cmake", "md",
];

struct FileText {
    path: String,
    text: String,
}

fn collect(root: &Path) -> Vec<FileText> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if files.len() >= MAX_FILES {
                return files;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            let suffix = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let known_name = matches!(
                name.as_str(),
                "Makefile" | "makefile" | "CMakeLists.txt" | "Dockerfile" | "requirements.txt"
            );
            if !known_name && !TEXT_SUFFIXES.contains(&suffix.as_str()) {
                continue;
            }
            if entry.metadata().map(|meta| meta.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            files.push(FileText {
                path: relative,
                text,
            });
        }
    }
    files
}

fn find<'a>(files: &'a [FileText], name: &str) -> Option<&'a FileText> {
    files
        .iter()
        .find(|file| file.path == name || file.path.ends_with(&format!("/{name}")))
}

fn toml_section_keys(text: &str, section: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed.trim_start_matches('[').trim_end_matches(']').trim() == section;
            continue;
        }
        if inside
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && let Some((key, _)) = trimmed.split_once('=')
        {
            keys.push(key.trim().trim_matches('"').to_owned());
        }
    }
    keys
}

fn json_dependency_keys(text: &str, field: &str) -> Vec<String> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| {
            value[field]
                .as_object()
                .map(|map| map.keys().cloned().collect())
        })
        .unwrap_or_default()
}

/// 识别结果只作为配置建议；未识别项进入 `missing`，由人工补充后版本化复用。
pub fn detect(root: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .with_context(|| format!("目标目录不存在：{}", root.display()))?;
    let files = collect(&root);
    let mut build = Vec::new();
    let mut dependencies = Vec::new();
    let mut entries = Vec::new();
    let mut inputs = Vec::new();

    if let Some(manifest) = find(&files, "Cargo.toml") {
        build.push(json!({"system":"cargo","manifest":manifest.path,
            "commands":["cargo build --release"],"evidence":"Cargo.toml"}));
        let deps = toml_section_keys(&manifest.text, "dependencies");
        if !deps.is_empty() {
            dependencies.push(json!({"manager":"cargo","count":deps.len(),
                "sample":deps.iter().take(MAX_SAMPLE).collect::<Vec<_>>()}));
        }
    }
    if let Some(manifest) = find(&files, "package.json") {
        let mut commands = vec!["npm install".to_owned(), "npm run start".to_owned()];
        if manifest.text.contains("\"build\"") {
            commands.push("npm run build".into());
        }
        build.push(json!({"system":"node","manifest":manifest.path,
            "commands":commands,"evidence":"package.json"}));
        let mut deps = json_dependency_keys(&manifest.text, "dependencies");
        deps.extend(json_dependency_keys(&manifest.text, "devDependencies"));
        if !deps.is_empty() {
            dependencies.push(json!({"manager":"npm","count":deps.len(),
                "sample":deps.iter().take(MAX_SAMPLE).collect::<Vec<_>>()}));
        }
    }
    if let Some(manifest) = find(&files, "pyproject.toml").or_else(|| find(&files, "setup.py")) {
        build.push(json!({"system":"python","manifest":manifest.path,
            "commands":["python -m pip install -e ."],"evidence":"pyproject.toml/setup.py"}));
        let deps = toml_section_keys(&manifest.text, "project.dependencies");
        let deps = if deps.is_empty() {
            toml_section_keys(&manifest.text, "dependencies")
        } else {
            deps
        };
        if !deps.is_empty() {
            dependencies.push(json!({"manager":"pip","count":deps.len(),
                "sample":deps.iter().take(MAX_SAMPLE).collect::<Vec<_>>()}));
        }
    }
    if let Some(requirements) = find(&files, "requirements.txt") {
        let deps: Vec<String> = requirements
            .text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                line.split(['=', '<', '>', '[', ' '])
                    .next()
                    .unwrap_or(line)
                    .to_owned()
            })
            .filter(|name| !name.is_empty())
            .collect();
        if !deps.is_empty() {
            dependencies.push(json!({"manager":"pip","manifest":requirements.path,
                "count":deps.len(),"sample":deps.iter().take(MAX_SAMPLE).collect::<Vec<_>>()}));
        }
    }
    if let Some(makefile) = find(&files, "Makefile").or_else(|| find(&files, "makefile")) {
        build.push(json!({"system":"make","manifest":makefile.path,
            "commands":["make"],"evidence":"Makefile"}));
    }
    if let Some(cmake) = find(&files, "CMakeLists.txt") {
        build.push(json!({"system":"cmake","manifest":cmake.path,
            "commands":["cmake -B build","cmake --build build"],"evidence":"CMakeLists.txt"}));
    }
    if let Some(gomod) = find(&files, "go.mod") {
        build.push(json!({"system":"go","manifest":gomod.path,
            "commands":["go build ./..."],"evidence":"go.mod"}));
    }

    for file in &files {
        let suffix = file
            .path
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let text = &file.text;
        let mut entry = |kind: &str, evidence: &str| {
            if entries.len() < 16 {
                entries.push(json!({"path":file.path,"kind":kind,"evidence":evidence}));
            }
        };
        let mut input = |kind: &str, evidence: &str| {
            if inputs.len() < 16 {
                inputs.push(json!({"path":file.path,"kind":kind,"evidence":evidence}));
            }
        };
        match suffix.as_str() {
            "py" => {
                if text.contains("__main__") {
                    entry("MAIN", "__main__");
                }
                if text.contains("argparse") || text.contains("sys.argv") {
                    input("ARGV", "argparse/sys.argv");
                }
                if text.contains("click.") || text.contains("@click") {
                    input("ARGV", "click");
                }
                if text.contains("sys.stdin") || text.contains("input(") {
                    input("STDIN", "stdin/input()");
                }
                if text.contains("flask") || text.contains("fastapi") || text.contains("uvicorn") {
                    input("HTTP", "flask/fastapi");
                }
            }
            "rs" => {
                if text.contains("fn main(") {
                    entry("MAIN", "fn main");
                }
                if text.contains("std::env::args") || text.contains("clap") {
                    input("ARGV", "std::env::args/clap");
                }
                if text.contains("axum") || text.contains("actix") || text.contains("warp") {
                    input("HTTP", "axum/actix/warp");
                }
            }
            "c" | "cc" | "cpp" => {
                if text.contains("int main(") {
                    entry("MAIN", "int main");
                }
                if text.contains("getopt") || text.contains("argc") {
                    input("ARGV", "getopt/argc");
                }
                if text.contains("fopen(") || text.contains("std::ifstream") {
                    input("FILE", "fopen/ifstream");
                }
            }
            "go" => {
                if text.contains("func main(") {
                    entry("MAIN", "func main");
                }
                if text.contains("os.Args") || text.contains("flag.") {
                    input("ARGV", "os.Args/flag");
                }
                if text.contains("net/http") || text.contains("gin.") {
                    input("HTTP", "net/http/gin");
                }
            }
            "js" | "ts" | "tsx" => {
                if text.contains("process.argv") {
                    input("ARGV", "process.argv");
                }
                if text.contains("express(")
                    || text.contains("app.listen")
                    || text.contains("fastify")
                {
                    input("HTTP", "express/fastify");
                }
            }
            _ => {}
        }
    }
    let mut invalid_package_main = None;
    if let Some(manifest) = find(&files, "package.json")
        && let Some(bin) = serde_json::from_str::<Value>(&manifest.text)
            .ok()
            .and_then(|value| value.get("main").and_then(Value::as_str).map(str::to_owned))
    {
        if relative_path(&bin).is_ok() {
            entries.push(json!({"path":bin,"kind":"MAIN","evidence":"package.json main"}));
        } else {
            invalid_package_main = Some(bin);
        }
    }

    let mut missing = Vec::new();
    if build.is_empty() {
        missing.push("未识别到构建系统：请补充构建命令或声明使用的工具链（如 Cargo.toml/package.json/pyproject.toml/Makefile）".to_owned());
    }
    if entries.is_empty() {
        missing
            .push("未识别到入口：请补充正常启动入口（如 main/__main__/bin 的相对路径）".to_owned());
    }
    if inputs.is_empty() {
        missing.push("未识别到输入接口：请补充正常输入方式（argv/stdin/文件参数/HTTP）".to_owned());
    }
    if dependencies.is_empty() {
        missing.push("未识别到依赖清单：请补充依赖文件或运行环境要求".to_owned());
    }
    if let Some(path) = invalid_package_main {
        missing.push(format!(
            "package.json main 不是目标树内的安全相对路径：{path}"
        ));
    }
    if build.len() > 1 {
        missing.push("识别到多个构建系统，需要人工确认实际使用的一个".to_owned());
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    entries.dedup_by(|a, b| a["path"] == b["path"] && a["kind"] == b["kind"]);
    inputs.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    inputs.dedup_by(|a, b| a["path"] == b["path"] && a["kind"] == b["kind"]);

    Ok(json!({
        "schema_version": 1,
        "config_version": "runconfig-1",
        "platform": "windows-x64",
        "source": "AUTO_DETECTED",
        "build": build,
        "entries": entries,
        "inputs": inputs,
        "dependencies": dependencies,
        "missing": missing,
        "complete": missing.is_empty(),
        "target_executed": false,
        "limitations": [
            "只做静态识别，未实际构建或运行目标",
            "识别结果不是漏洞位置、CVE 或参考 PoC；配置缺失不阻断独立静态审计",
            "未识别项需人工补充后版本化复用，不得静默重解释旧配置",
        ],
    }))
}

/// 供调用方定位目标树中的相对路径，拒绝越界与宿主绝对路径。
pub fn relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    anyhow::ensure!(
        !path.is_absolute()
            && !value.contains('\\')
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "配置中的目标路径必须是目标树内的相对路径"
    );
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn detects_python_build_entry_inputs_and_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        write(
            temp.path(),
            "pyproject.toml",
            "[project]\nname = \"demo\"\n\n[project.dependencies]\nrequests = \">=2\"\n",
        );
        write(
            temp.path(),
            "requirements.txt",
            "flask\nrequests\n# comment\n",
        );
        write(
            temp.path(),
            "app/main.py",
            "import argparse\nif __name__ == \"__main__\":\n    argparse.ArgumentParser().parse_args()\n",
        );
        let config = detect(temp.path()).unwrap();
        assert_eq!(config["source"], "AUTO_DETECTED");
        assert!(
            config["build"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["system"] == "python")
        );
        assert!(
            config["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["path"] == "app/main.py" && item["kind"] == "MAIN")
        );
        assert!(
            config["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["kind"] == "ARGV")
        );
        assert!(
            config["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["manager"] == "pip" && item["count"] == 2)
        );
        assert_eq!(config["complete"], true, "{config}");
        assert_eq!(config["target_executed"], false);
    }

    #[test]
    fn missing_information_is_listed_and_never_blocks_static_analysis() {
        let temp = tempfile::tempdir().unwrap();
        write(temp.path(), "src/lib.rs", "pub fn helper() -> u32 { 1 }\n");
        let config = detect(temp.path()).unwrap();
        let missing = config["missing"].as_array().unwrap();
        assert!(
            missing
                .iter()
                .any(|item| item.as_str().unwrap().contains("构建系统"))
        );
        assert!(
            missing
                .iter()
                .any(|item| item.as_str().unwrap().contains("入口"))
        );
        assert_eq!(config["complete"], false);
        assert!(config["build"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rust_project_uses_manifest_entries_and_cli_inputs() {
        let temp = tempfile::tempdir().unwrap();
        write(
            temp.path(),
            "Cargo.toml",
            "[package]\nname = \"demo\"\n\n[dependencies]\nserde = \"1\"\ntokio = \"1\"\n",
        );
        write(
            temp.path(),
            "src/main.rs",
            "fn main() { for arg in std::env::args() { println!(\"{arg}\"); } }\n",
        );
        let config = detect(temp.path()).unwrap();
        assert!(
            config["build"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["system"] == "cargo")
        );
        assert!(
            config["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["path"] == "src/main.rs")
        );
        assert!(
            config["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["kind"] == "ARGV")
        );
        assert!(
            config["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["count"] == 2)
        );
    }

    #[test]
    fn target_paths_must_stay_inside_the_tree() {
        assert!(relative_path("app/main.py").is_ok());
        assert!(relative_path("..\\windows\\system32\\cmd.exe").is_err());
        assert!(relative_path("C:\\Windows\\cmd.exe").is_err());
        assert!(relative_path("app/../../etc/passwd").is_err());
    }

    #[test]
    fn package_json_main_must_be_a_safe_relative_path() {
        let temp = tempfile::tempdir().unwrap();
        write(
            temp.path(),
            "package.json",
            r#"{ "main": "C:\\Windows\\system32\\cmd.exe", "dependencies": { "express": "^4" } }"#,
        );
        write(temp.path(), "server.js", "process.argv\napp.listen(8080)\n");
        let config = detect(temp.path()).unwrap();
        assert!(
            !config["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["path"] == "C:\\Windows\\system32\\cmd.exe")
        );
        assert!(
            config["missing"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str().unwrap().contains("package.json main"))
        );
    }
}
