// PoC p07-修复版：同一场景对修复后的 realpath(mfDir, from)（37d95157）逐用例实测。
//
// 修复思路：相对路径优先解析到 Modelfile 所在目录。下面的函数段按边界从
// fixed-images.go 抽取，字节一致。三个用例：
//   A 相对文件名只存在于服务 CWD（不在模型目录）→ 修复版回落到 CWD 相对解析（逃逸依旧）
//   B 绝对路径 → filepath.Abs 原样返回（从未被约束）
//   C 文件确实存在于模型目录 → 解析到模型目录内（修复真正覆盖到的情形）
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

	serverCwd := filepath.Join(base, "server-cwd")
	modelDir := filepath.Join(base, "models")
	if err := os.MkdirAll(serverCwd, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		panic(err)
	}

	// 敏感文件 1：只在服务 CWD 下
	secret := filepath.Join(serverCwd, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET-OUTSIDE-MODEL-DIR"), 0o644); err != nil {
		panic(err)
	}
	// 敏感文件 2：绝对路径目标（模拟“任意绝对路径可读”）
	absolute := filepath.Join(base, "absolute-secret.txt")
	if err := os.WriteFile(absolute, []byte("SECRET-ABSOLUTE-PATH"), 0o644); err != nil {
		panic(err)
	}
	// 对照用的合法文件：就在模型目录里
	if err := os.WriteFile(filepath.Join(modelDir, "local.txt"), []byte("LOCAL-IN-MODEL-DIR"), 0o644); err != nil {
		panic(err)
	}
	if err := os.Chdir(serverCwd); err != nil {
		panic(err)
	}

	report := func(label, arg string) {
		resolved := realpath(modelDir, arg)
		data, readErr := os.ReadFile(resolved)
		fmt.Printf("[%s] 参数=%q\n  realpath -> %s\n", label, arg, resolved)
		if readErr == nil {
			fmt.Printf("  读取成功，内容 = %q\n", strings.TrimSpace(string(data)))
		} else {
			fmt.Printf("  读取失败: %v\n", readErr)
		}
	}

	fmt.Printf("服务 CWD         : %s\n", serverCwd)
	fmt.Printf("Modelfile 所在目录: %s\n\n", modelDir)
	report("A 相对路径（文件只在 CWD）", "secret.txt")
	fmt.Println()
	report("B 绝对路径", absolute)
	fmt.Println()
	report("C 文件在模型目录内", "local.txt")
}
func realpath(mfDir, from string) string {
	abspath, err := filepath.Abs(from)
	if err != nil {
		return from
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return abspath
	}

	if from == "~" {
		return home
	} else if strings.HasPrefix(from, "~/") {
		return filepath.Join(home, from[2:])
	}

	if _, err := os.Stat(filepath.Join(mfDir, from)); err == nil {
		// this is a file relative to the Modelfile
		return filepath.Join(mfDir, from)
	}

	return abspath
}
