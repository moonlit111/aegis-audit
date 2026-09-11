// PoC p08：ollama auth/auth.go 的 NewNonce 未校验 length（对照池 p08 的附加发现）。
//
// 下方的 NewNonce 段从 vulnerable-auth.go（ceac416e）按函数边界抽取，字节一致；
// 两版 auth.go 的该函数完全相同（上游修复没动它）。组件级演示：
//   - 正常长度 16：返回随机 nonce（现有调用方用的就是常量 16）
//   - 极端长度：make([]byte, length) 直接 panic（内存耗尽/越界型 DoS）
//
// 注意（诚实口径）：在当时代码树里，两处调用方都硬编码传 16
// （app/lifecycle/updater.go:52、server/auth.go:42），**没有攻击者可控的
// 长度入口**——所以这是"函数缺上界校验"，不是可远程触发的漏洞。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math"
)

func main() {
	// 正常用法
	nonce, err := NewNonce(rand.Reader, 16)
	fmt.Printf("[正常] NewNonce(rand.Reader, 16) -> %q err=%v\n", nonce, err)

	// 极端值 1：math.MaxInt64
	demo("math.MaxInt64", math.MaxInt64)
	// 极端值 2：负数
	demo("负数 -1", -1)
}

func demo(label string, length int) {
	defer func() {
		if caught := recover(); caught != nil {
			fmt.Printf("[极端] length=%s -> panic: %v\n", label, caught)
		}
	}()
	nonce, err := NewNonce(rand.Reader, length)
	fmt.Printf("[极端] length=%s -> 返回 %d 字节 nonce（未 panic）err=%v\n", label, len(nonce), err)
}
func NewNonce(r io.Reader, length int) (string, error) {
	nonce := make([]byte, length)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(nonce), nil
}
