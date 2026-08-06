package tencentcos

import (
	"context"
	"errors"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
)

// TestStoreContract 验证 COS 官方 SDK 的请求映射和签名能力。
func TestStoreContract(t *testing.T) {
	var mutex sync.Mutex
	requests := make(map[string]*http.Request)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		request.Body = io.NopCloser(strings.NewReader(string(body)))
		mutex.Lock()
		requests[request.Method] = request.Clone(request.Context())
		requests[request.Method].Body = io.NopCloser(strings.NewReader(string(body)))
		mutex.Unlock()
		writer.Header().Set("ETag", `"etag"`)
		writer.Header().Set("x-cos-version-id", "version")
		writer.Header().Set("x-cos-hash-crc64ecma", strconv.FormatUint(crc64.Checksum(body, crc64.MakeTable(crc64.ECMA)), 10))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store, err := New(Config{
		Bucket:    "bucket-1250000000",
		Endpoint:  server.URL,
		SecretID:  "secret-id",
		SecretKey: "secret-key",
	})
	if err != nil {
		t.Fatalf("create COS store: %v", err)
	}
	body := strings.NewReader("content")
	// 预先移动游标，验证适配器会自行回退到内容起点。
	if _, err := body.Seek(3, io.SeekStart); err != nil {
		t.Fatalf("seek COS source: %v", err)
	}
	result, err := store.Put(context.Background(), uploadkit.PutObject{
		Key:                "docs/file.txt",
		Body:               body,
		Size:               body.Size(),
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
		Metadata:           map[string]string{"owner": "tenant"},
	})
	if err != nil {
		t.Fatalf("put COS object: %v", err)
	}
	if result.ETag != "etag" || result.VersionID != "version" {
		t.Fatalf("unexpected stored object: %+v", result)
	}
	mutex.Lock()
	putRequest := requests[http.MethodPut]
	mutex.Unlock()
	if putRequest == nil {
		t.Fatal("COS PUT request was not received")
	}
	putBody, _ := io.ReadAll(putRequest.Body)
	if string(putBody) != "content" || putRequest.Header.Get("If-None-Match") != "*" {
		t.Fatalf("unexpected COS PUT request: body=%q headers=%v", putBody, putRequest.Header)
	}
	if putRequest.Header.Get(checksumMetadataKey) == "" || putRequest.Header.Get("Authorization") == "" {
		t.Fatal("COS checksum metadata or authorization is missing")
	}
	if err = store.Ping(context.Background()); err != nil {
		t.Fatalf("ping COS store: %v", err)
	}
	if err = store.Delete(context.Background(), "docs/file.txt"); err != nil {
		t.Fatalf("delete COS object: %v", err)
	}
	signedURL, err := store.SignedURL(context.Background(), "docs/file.txt", time.Minute)
	if err != nil || !strings.Contains(signedURL, "q-signature=") {
		t.Fatalf("sign COS URL: %s %v", signedURL, err)
	}
}

// TestStoreMapsObjectExists 验证 COS 条件写入冲突映射为统一对象已存在错误。
func TestStoreMapsObjectExists(t *testing.T) {
	// 创建固定返回前置条件失败的测试服务端。
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/xml")
		writer.WriteHeader(http.StatusPreconditionFailed)
		_, _ = io.WriteString(writer, `<Error><Code>PreconditionFailed</Code><Message>object exists</Message></Error>`)
	}))
	// 测试结束后关闭服务端。
	defer server.Close()
	// 创建默认禁止覆盖的 COS 适配器。
	store, err := New(Config{
		Bucket:    "bucket-1250000000",
		Endpoint:  server.URL,
		SecretID:  "secret-id",
		SecretKey: "secret-key",
	})
	if err != nil {
		t.Fatalf("create COS store: %v", err)
	}
	// 构建完整有效的写入参数。
	body := strings.NewReader("content")
	_, err = store.Put(context.Background(), uploadkit.PutObject{
		Key:                "docs/file.txt",
		Body:               body,
		Size:               body.Size(),
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
	})
	// 调用方必须能够使用 errors.Is 判断统一错误。
	if !errors.Is(err, uploadkit.ErrObjectExists) {
		t.Fatalf("expected object exists error, got: %v", err)
	}
}

// TestNewRejectsNegativeRetry 验证负数重试配置不会被静默忽略。
func TestNewRejectsNegativeRetry(t *testing.T) {
	_, err := New(Config{
		Bucket:        "bucket-1250000000",
		Endpoint:      "https://cos.example.com",
		SecretID:      "secret-id",
		SecretKey:     "secret-key",
		RetryCount:    -1,
		RetryInterval: -1,
	})
	if !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
}
