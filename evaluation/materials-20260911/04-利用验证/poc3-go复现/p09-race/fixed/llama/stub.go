// Package llama 是 github.com/ollama/ollama/llama 的替身：只提供 runner/image.go
// 用到的类型与方法。真实的 ClipContext/MllamaContext 是 cgo 绑定（依赖 llama.cpp），
// 本 PoC 用纯 Go 假实现替代，被验证的并发逻辑（image.go）是原样代码。
package llama

type Context struct{}

type Model struct{}

func (c *Context) Model() *Model { return &Model{} }

func (m *Model) NEmbd() int { return 0 }

type ClipContext struct{}

func (c *ClipContext) NewEmbed(_ *Context, _ []byte) ([][]float32, error) {
	return [][]float32{{0}}, nil
}

func (c *ClipContext) Free() {}

type MllamaContext struct{}

func (c *MllamaContext) NewEmbed(_ *Context, _ []byte, _ int) ([][]float32, error) {
	return [][]float32{{0}}, nil
}

func (c *MllamaContext) Free() {}

func (c *MllamaContext) EmbedSize(_ *Context) int { return 0 }

func GetModelArch(modelPath string) (string, error) { return "clip", nil }

func NewClipContext(_ *Context, _ string) (*ClipContext, error) { return &ClipContext{}, nil }

func NewMllamaContext(_ *Context, _ string) (*MllamaContext, error) { return &MllamaContext{}, nil }
