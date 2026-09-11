package server

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
)

// TestPrepareMissingContentLength：HEAD 响应没有 Content-Length 时，
// Prepare 里的 ParseInt 失败被忽略（b.Total = 0）→ 分片循环一次都不进
// → b.Parts 为空。随后 Prepare 末尾的日志行直接取 b.Parts[0].Size：
//
//	漏洞版 63f0269f：日志行在 if 之外  → index out of range panic
//	修复版 d8932c55：日志行移入 else   → 不再 panic
func TestPrepareMissingContentLength(t *testing.T) {
	dir := t.TempDir()
	requestURL, err := url.Parse("http://registry.invalid/v2/library/m/blob/sha256:0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	blob := &blobDownload{
		Name:   filepath.Join(dir, "blob"),
		Digest: "sha256:0123456789abcdef",
	}

	var prepareErr error
	caught := func() (recovered any) {
		defer func() { recovered = recover() }()
		prepareErr = blob.Prepare(context.Background(), requestURL, &registryOptions{})
		return nil
	}()

	if caught != nil {
		t.Logf("POC_RESULT=PANIC  %v", caught)
		t.Log("（完整 panic 栈见 TestPreparePanicRaw，栈中直接指出 server/download.go:175）")
	} else {
		t.Logf("POC_RESULT=NO_PANIC  Prepare 正常返回 err=%v", prepareErr)
	}
}

// TestPreparePanicRaw 故意不 recover：让运行时打印完整 panic 栈——
// 栈里会直接指出 server/download.go:175（vuln）的越界行。
// 漏洞版整场以非零码结束，属预期证据；修复版正常通过（NO_PANIC）。
func TestPreparePanicRaw(t *testing.T) {
	dir := t.TempDir()
	requestURL, err := url.Parse("http://registry.invalid/v2/library/m/blob/sha256:0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	blob := &blobDownload{
		Name:   filepath.Join(dir, "blob"),
		Digest: "sha256:0123456789abcdef",
	}
	if err := blob.Prepare(context.Background(), requestURL, &registryOptions{}); err != nil {
		t.Logf("POC_RESULT=NO_PANIC  Prepare 正常返回 err=%v", err)
		return
	}
	t.Log("POC_RESULT=NO_PANIC  Prepare 正常返回 err=nil")
}
