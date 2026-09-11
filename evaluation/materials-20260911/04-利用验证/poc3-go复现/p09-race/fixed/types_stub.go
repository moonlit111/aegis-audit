package main

// input 类型在 runner 的其它文件里定义；本 PoC 只用到它的 embed 字段
// （image.go 的 NeedCrossAttention 里 `input.embed != nil`）。
type input struct {
	embed [][]float32
}
