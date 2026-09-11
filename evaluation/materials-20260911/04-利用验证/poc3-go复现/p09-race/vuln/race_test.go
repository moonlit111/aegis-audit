package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ollama/ollama/llama"
)

// TestImageEmbedRace：NewEmbed 在加锁**之前**调用 c.hashImage(data)（源码里
// hash 一行在 c.mu.Lock() 之前），而 hashImage 复用 ImageContext 上共享的
// maphash.Hash 字段——并发调用即数据竞争。本测试并发跑真实的 NewEmbed
// （视觉后端为纯 Go 桩），交给 -race 检测。
func TestImageEmbedRace(t *testing.T) {
	ctx, err := NewImageContext(&llama.Context{}, "stub-model")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				if _, err := ctx.NewEmbed(nil, []byte(fmt.Sprintf("image-%d-%d", w, i)), 0); err != nil {
					t.Errorf("NewEmbed: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	t.Log("并发 NewEmbed 完成（若存在数据竞争，-race 会在上方输出 WARNING: DATA RACE）")
}
