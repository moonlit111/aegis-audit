# Windows 独立运行

Windows 便携版的入口是 `AegisAudit.exe`。整个解压目录构成应用，不是只复制一个 EXE。启动器内置 Python 运行时，并随包提供 Git、JDK、Ghidra、Windows Semgrep、原生服务及浏览器资源；使用者不需要另装 Python、Rust、Node、Java 或 Git，也不需要 WSL、Docker 或另一台电脑提供控制服务。

本页描述构建后的部署约定。2026-09-09 已在本机完成便携包逐文件核验、中文/空格路径重定位、清除开发工具 PATH 后启停、真实静态工具、重复启动、端口冲突、正常退出、强制退出及恢复检查。记录见[Windows 实机验证记录](Windows实机验证记录.md)。这不是干净虚拟机部署或完整课程验收；Windows 原生动态隔离仍未完成。

## 使用

1. 将 `aegis-audit-0.2.0-windows-amd64-standalone.zip` 完整解压到可写的本地目录，例如 `C:\AegisAudit`。中文与空格目录已经过本机实际验证；为兼容 Ghidra 的 Windows 批处理入口，不要在安装路径中使用 `%!&|<>^` 等 shell 特殊字符，也不要放在只读或系统安装目录。
2. 双击 `AegisAudit.exe`。应用启动本地服务和执行器，打开浏览器，并保留系统托盘图标。默认使用 `127.0.0.1:7331`；被其他程序占用时选择后续空闲本地端口，不停止已有程序。
3. 托盘菜单提供打开应用、DeepSeek 模型配置、日志目录和退出。关闭浏览器不会停止任务；退出托盘应用才会停止本次启动的服务及执行器。
4. 模型密钥通过本机原生密码输入框，使用当前 Windows 账户的 DPAPI 加密后原子写入 `.data/server/deepseek.token`，不通过网页表单、命令行参数或源码传递。连接检测会使用官方 DeepSeek API，产生实际用量。更换账户/电脑后如果无法解密，应重新配置；旧明文文件仅保留读取兼容，重新保存会转换为加密格式。

项目、证据、模型配置和日志都保存在解压目录的 `.data/` 下。该目录不进入发布压缩包。升级前退出应用并备份整个 `.data/`，不要只备份 SQLite 主文件。分发应用时使用构建出的原始 ZIP，不要把已使用目录连同密钥重新打包。

## 启停与诊断

同一目录重复启动会打开已有实例，不再启动第二套服务。启动器通过 Windows Job Object 拥有子进程；正常退出先发送退出信号，超时或启动器异常退出时回收其进程树。不同安装目录使用不同实例标识。实例互斥量和每次启动的唯一命名 Job 使用 Windows 全局命名空间，避免跨桌面会话误判原进程组已不存在。

执行器只有在验证自己确实属于启用 kill-on-close 的命名 Job 后，才记录其所有权。重启遇到中断的导入/静态分析任务时，先核对机器身份并查询原 Job 的真实进程数；确认关闭或为空后保存恢复证据，将未完成任务记为失败，允许新任务继续，不自动重跑旧任务。旧版无所有权记录、仍有进程、机器身份不符，以及动态隔离任务均不能走这一自动恢复路径。

```powershell
.\AegisAudit.exe --stop
.\AegisAudit.exe --diagnostics .\doctor.json --non-interactive
.\AegisAudit.exe --port 7332
.\AegisAudit.exe --configure-model
```

诊断结果要逐项查看，命令退出 0 不表示所有可选能力都可用。应用尚未签名；Windows 的下载来源或 SmartScreen 提示不能作为签名验证通过的证据。发布包附整包 SHA-256 和 `PACKAGE-MANIFEST.json`；校验后再运行。

## 构建

在具备项目构建工具的 Windows 源码目录运行：

```powershell
py -3 scripts/manage.py build
py -3 scripts/package.py --standalone-windows --no-build
```

构建脚本从固定 URL 下载并核对便携 Python、MinGit 的 SHA-256；版本见 `tools/windows/versions.json`。启动器依赖固定于 `tools/windows/requirements.txt`，原生 Semgrep 依赖固定于 `tools/windows/semgrep-requirements.txt`。使用私有 Python 的安装模块入口，不依赖包含构建机绝对路径的 pip EXE 脚本。Java/Ghidra 沿用项目的已安装固定版本。包内保留上游许可证，并收集 Python 依赖的许可记录。构建工具不属于最终用户的前置条件。

## 尚未完成

本页描述 Windows 独立启动和静态分析/审计的部署方式，不将其等同于全部课程验收。当前 Linux 容器动态运行器尚未替换为经过实测的 Windows 原生隔离运行器；原生 PE 动态执行、自动保护处理、六项正式样本及完整项目验收仍未完成。Windows-only 全部交付必须继续完成这些工作，不能用便携打包或开发夹具结果替代。
