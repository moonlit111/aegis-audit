// Package api 是 github.com/ollama/ollama/api 的替身：只提供本 PoC 用到的类型。
package api

type ProgressResponse struct {
	Status    string `json:"status"`
	Digest    string `json:"digest,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Completed int64  `json:"completed,omitempty"`
}
