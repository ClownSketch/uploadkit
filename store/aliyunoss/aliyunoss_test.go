package aliyunoss

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
)

// mockClient 保存 OSS 适配器请求。
type mockClient struct {
	putRequest    *oss.PutObjectRequest     // putRequest 上传请求
	deleteRequest *oss.DeleteObjectRequest  // deleteRequest 删除请求
	headRequest   *oss.GetBucketInfoRequest // headRequest 检查请求
	putErr        error                     // putErr 模拟写入错误
}

// PutObject 记录上传请求。
func (m *mockClient) PutObject(ctx context.Context, request *oss.PutObjectRequest, options ...func(*oss.Options)) (*oss.PutObjectResult, error) {
	m.putRequest = request
	if m.putErr != nil {
		return nil, m.putErr
	}
	return &oss.PutObjectResult{ETag: oss.Ptr(`"etag"`), VersionId: oss.Ptr("version")}, nil
}

// DeleteObject 记录删除请求。
func (m *mockClient) DeleteObject(ctx context.Context, request *oss.DeleteObjectRequest, options ...func(*oss.Options)) (*oss.DeleteObjectResult, error) {
	m.deleteRequest = request
	return &oss.DeleteObjectResult{}, nil
}

// GetBucketInfo 记录 Bucket 检查请求。
func (m *mockClient) GetBucketInfo(ctx context.Context, request *oss.GetBucketInfoRequest, options ...func(*oss.Options)) (*oss.GetBucketInfoResult, error) {
	m.headRequest = request
	return &oss.GetBucketInfoResult{}, nil
}

// Presign 返回固定签名地址。
func (m *mockClient) Presign(ctx context.Context, request any, options ...func(*oss.PresignOptions)) (*oss.PresignResult, error) {
	return &oss.PresignResult{URL: "https://signed.example.com/object"}, nil
}

// TestStoreContract 验证 OSS 请求映射和可选能力。
func TestStoreContract(t *testing.T) {
	client := &mockClient{}
	store := &Store{
		client: client,
		bucket: "bucket",
	}
	body := strings.NewReader("content")
	// 预先移动游标，验证适配器会自行回退到内容起点。
	if _, err := body.Seek(3, io.SeekStart); err != nil {
		t.Fatalf("seek OSS source: %v", err)
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
		t.Fatalf("put OSS object: %v", err)
	}
	if result.ETag != "etag" || result.VersionID != "version" {
		t.Fatalf("unexpected stored object: %+v", result)
	}
	content, err := io.ReadAll(client.putRequest.Body)
	if err != nil || string(content) != "content" {
		t.Fatalf("unexpected request body: %q %v", content, err)
	}
	if oss.ToString(client.putRequest.ForbidOverwrite) != "true" || client.putRequest.Metadata[checksumMetadataKey] == "" {
		t.Fatalf("missing overwrite or checksum guard: %+v", client.putRequest)
	}
	if err = store.Delete(context.Background(), "docs/file.txt"); err != nil {
		t.Fatalf("delete OSS object: %v", err)
	}
	if err = store.Ping(context.Background()); err != nil {
		t.Fatalf("ping OSS store: %v", err)
	}
	if oss.ToString(client.deleteRequest.Key) != "docs/file.txt" || oss.ToString(client.headRequest.Bucket) != "bucket" {
		t.Fatal("delete or health request was not mapped")
	}
	signedURL, err := store.SignedURL(context.Background(), "docs/file.txt", time.Minute)
	if err != nil || signedURL != "https://signed.example.com/object" {
		t.Fatalf("sign OSS URL: %s %v", signedURL, err)
	}
}

// TestStoreMapsObjectExists 验证 OSS 禁止覆盖错误映射为统一对象已存在错误。
func TestStoreMapsObjectExists(t *testing.T) {
	// 模拟 OSS 返回前置条件失败。
	client := &mockClient{putErr: &oss.ServiceError{StatusCode: http.StatusPreconditionFailed, Code: "PreconditionFailed"}}
	// 默认禁止覆盖同名对象。
	store := &Store{client: client, bucket: "bucket"}
	// 构建完整有效的写入参数。
	body := strings.NewReader("content")
	_, err := store.Put(context.Background(), uploadkit.PutObject{
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
