// 本文件是 PoC 桩：补齐 download.go 在本仓其余文件里的依赖符号。
// - registryOptions 按上游 server/images.go 的字段原样重写；
// - makeRequestWithRetry 用固定响应替代真实 HTTP 拉取：返回一个**不含
//   Content-Length 头**的 200 响应——这正是触发条件（HEAD 拿不到长度）。
// 除本文件与 api/format/errgroup 替身外，download.go 是原样代码。
package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

// 以下三个符号在上游位于 server 包的其它文件（modelpath.go、sparse_*.go），
// 这里按原签名补桩；本 PoC 触发的 Prepare 路径不会用到它们的实现细节。

// 上游 modelpath.go:17：字段与 download.go 用到的两个方法按原样抄录。
type ModelPath struct {
	ProtocolScheme string
	Registry       string
	Namespace      string
	Repository     string
	Tag            string
}

// 上游 modelpath.go:82，字节一致。
func (mp ModelPath) GetNamespaceRepository() string {
	return fmt.Sprintf("%s/%s", mp.Namespace, mp.Repository)
}

// 上游 modelpath.go:110，字节一致。
func (mp ModelPath) BaseURL() *url.URL {
	return &url.URL{
		Scheme: mp.ProtocolScheme,
		Host:   mp.Registry,
	}
}

// 上游 modelpath.go:126（downloadBlob 里取 blob 落盘路径，本 PoC 不经过）。
func GetBlobsPath(digest string) (string, error) {
	return filepath.Join(os.TempDir(), "ollama-blobs-poc", digest), nil
}

// 上游 sparse_common.go:7 / sparse_windows.go:9（设置稀疏文件，无返回值的空操作即可）。
func setSparse(*os.File) {}

type registryOptions struct {
	Insecure      bool
	Username      string
	Password      string
	Token         string
	CheckRedirect func(req *http.Request, via []*http.Request) error
}

func makeRequestWithRetry(ctx context.Context, method string, requestURL *url.URL, headers http.Header, body io.ReadSeeker, regOpts *registryOptions) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    &http.Request{Method: method, URL: requestURL},
	}, nil
}
