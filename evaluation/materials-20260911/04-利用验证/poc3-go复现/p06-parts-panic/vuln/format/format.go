// Package format 是 github.com/ollama/ollama/format 的替身（仅本 PoC 用到的部分）。
package format

import "fmt"

const MegaByte = 1024 * 1024

func HumanBytes(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}
