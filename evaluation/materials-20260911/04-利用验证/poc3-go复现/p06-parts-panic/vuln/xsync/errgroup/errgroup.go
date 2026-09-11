// Package errgroup 是 golang.org/x/sync/errgroup 的极简替身：
// 只实现本 PoC 用到的 API（WithContext / SetLimit / Go / Wait），语义与原版一致。
package errgroup

import (
	"context"
	"sync"
)

type Group struct {
	cancel func()
	wg     sync.WaitGroup
	sem    chan struct{}
	mu     sync.Mutex
	err    error
}

func WithContext(ctx context.Context) (*Group, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return &Group{cancel: cancel}, ctx
}

func (g *Group) SetLimit(n int) {
	if n > 0 {
		g.sem = make(chan struct{}, n)
	}
}

func (g *Group) Go(fn func() error) {
	if g.sem != nil {
		g.sem <- struct{}{}
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if g.sem != nil {
			defer func() { <-g.sem }()
		}
		if err := fn(); err != nil {
			g.mu.Lock()
			if g.err == nil {
				g.err = err
				if g.cancel != nil {
					g.cancel()
				}
			}
			g.mu.Unlock()
		}
	}()
}

func (g *Group) Wait() error {
	g.wg.Wait()
	if g.cancel != nil {
		g.cancel()
	}
	return g.err
}
