# 动态执行开发夹具

本目录是可控的组件验证与模糊测试输入，不是课程正式软件。formatter.py 用无网络依赖的 printf 输入边界检验命令注入及修复；input.c 为标准输入越界与修复对照。它们与 tests/fixtures/audit 中的路径、权限及内存夹具共同检查实际运行器。

复验命令：`python3 scripts/check_runtime.py`。需要已构建的服务/执行器及 `aegis-runtime:0.2.0` Linux amd64 镜像。每次使用独立数据库、只读目标、断网容器及新测试目录；配置、正常输入、重复输入、日志、哈希和结果保留在 `.data/verification/runtime-*`。
