package huaweiobs

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
)

// TestStoreContract 验证 OBS 官方 SDK 的请求映射和签名能力。
func TestStoreContract(t *testing.T) {
	var mutex sync.Mutex
	requests := make(map[string]*http.Request)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mutex.Lock()
		requests[request.Method] = request.Clone(request.Context())
		requests[request.Method].Body = io.NopCloser(strings.NewReader(string(body)))
		mutex.Unlock()
		writer.Header().Set("ETag", `"etag"`)
		writer.Header().Set("x-obs-version-id", "version")
		writer.Header().Set("x-obs-request-id", "request-id")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store, err := New(Config{
		Region:          "cn-north-4",
		Bucket:          "bucket",
		Endpoint:        server.URL,
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		UsePathStyle:    true,
	})
	if err != nil {
		t.Fatalf("create OBS store: %v", err)
	}
	body := strings.NewReader("content")
	// 预先移动游标，验证适配器会自行回退到内容起点。
	if _, err := body.Seek(3, io.SeekStart); err != nil {
		t.Fatalf("seek OBS source: %v", err)
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
		t.Fatalf("put OBS object: %v", err)
	}
	if result.ETag != "etag" || result.VersionID != "version" {
		t.Fatalf("unexpected stored object: %+v", result)
	}
	mutex.Lock()
	putRequest := requests[http.MethodPut]
	mutex.Unlock()
	if putRequest == nil {
		t.Fatal("OBS PUT request was not received")
	}
	putBody, _ := io.ReadAll(putRequest.Body)
	if string(putBody) != "content" || !strings.Contains(putRequest.URL.Path, "/bucket/docs/file.txt") {
		t.Fatalf("unexpected OBS PUT request: path=%s body=%q", putRequest.URL.Path, putBody)
	}
	checksumHeader := putRequest.Header.Get("x-obs-meta-" + checksumMetadataKey)
	if checksumHeader == "" {
		checksumHeader = putRequest.Header.Get("x-amz-meta-" + checksumMetadataKey)
	}
	if checksumHeader == "" || putRequest.Header.Get("Authorization") == "" {
		t.Fatalf("OBS checksum metadata or authorization is missing: %v", putRequest.Header)
	}
	if err = store.Ping(context.Background()); err != nil {
		t.Fatalf("ping OBS store: %v", err)
	}
	if err = store.Delete(context.Background(), "docs/file.txt"); err != nil {
		t.Fatalf("delete OBS object: %v", err)
	}
	signedURL, err := store.SignedURL(context.Background(), "docs/file.txt", time.Minute)
	if err != nil || !strings.Contains(strings.ToLower(signedURL), "signature=") {
		t.Fatalf("sign OBS URL: %s %v", signedURL, err)
	}
}

// TestStoreHonorsContext 验证 OBS 每次请求使用调用方上下文。
func TestStoreHonorsContext(t *testing.T) {
	store, err := New(Config{
		Region:          "cn-north-4",
		Bucket:          "bucket",
		Endpoint:        "https://obs.example.com",
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		UsePathStyle:    true,
	})
	if err != nil {
		t.Fatalf("create OBS store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := strings.NewReader("content")
	_, err = store.Put(ctx, uploadkit.PutObject{
		Key:                "docs/file.txt",
		Body:               body,
		Size:               body.Size(),
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
	})
	if err == nil {
		t.Fatal("expected canceled OBS request")
	}
}
