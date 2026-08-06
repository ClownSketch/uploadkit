package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// mockClient 保存 S3 适配器请求。
type mockClient struct {
	putInput    *awss3.PutObjectInput    // putInput 上传请求
	deleteInput *awss3.DeleteObjectInput // deleteInput 删除请求
	headInput   *awss3.HeadBucketInput   // headInput 检查请求
	putErr      error                    // putErr 模拟写入错误
}

// PutObject 记录上传请求。
func (m *mockClient) PutObject(ctx context.Context, input *awss3.PutObjectInput, options ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	m.putInput = input
	if m.putErr != nil {
		return nil, m.putErr
	}
	return &awss3.PutObjectOutput{ETag: aws.String(`"etag"`), VersionId: aws.String("version")}, nil
}

// DeleteObject 记录删除请求。
func (m *mockClient) DeleteObject(ctx context.Context, input *awss3.DeleteObjectInput, options ...func(*awss3.Options)) (*awss3.DeleteObjectOutput, error) {
	m.deleteInput = input
	return &awss3.DeleteObjectOutput{}, nil
}

// HeadBucket 记录 Bucket 检查请求。
func (m *mockClient) HeadBucket(ctx context.Context, input *awss3.HeadBucketInput, options ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
	m.headInput = input
	return &awss3.HeadBucketOutput{}, nil
}

// mockPresigner 返回固定签名地址。
type mockPresigner struct{}

// PresignGetObject 创建测试签名地址。
func (m *mockPresigner) PresignGetObject(ctx context.Context, input *awss3.GetObjectInput, options ...func(*awss3.PresignOptions)) (*awsv4.PresignedHTTPRequest, error) {
	return &awsv4.PresignedHTTPRequest{URL: "https://signed.example.com/object"}, nil
}

// TestStoreContract 验证 S3 请求映射和可选能力。
func TestStoreContract(t *testing.T) {
	client := &mockClient{}
	store := &Store{
		client:    client,
		presigner: &mockPresigner{},
		bucket:    "bucket",
	}
	body := strings.NewReader("content")
	// 预先移动游标，验证适配器会自行回退到内容起点。
	if _, err := body.Seek(3, io.SeekStart); err != nil {
		t.Fatalf("seek S3 source: %v", err)
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
		t.Fatalf("put S3 object: %v", err)
	}
	if result.ETag != "etag" || result.VersionID != "version" {
		t.Fatalf("unexpected stored object: %+v", result)
	}
	content, err := io.ReadAll(client.putInput.Body)
	if err != nil || string(content) != "content" {
		t.Fatalf("unexpected request body: %q %v", content, err)
	}
	if aws.ToString(client.putInput.IfNoneMatch) != "*" || client.putInput.Metadata[checksumMetadataKey] == "" {
		t.Fatalf("missing overwrite or checksum guard: %+v", client.putInput)
	}
	if err = store.Delete(context.Background(), "docs/file.txt"); err != nil {
		t.Fatalf("delete S3 object: %v", err)
	}
	if err = store.Ping(context.Background()); err != nil {
		t.Fatalf("ping S3 store: %v", err)
	}
	if aws.ToString(client.deleteInput.Key) != "docs/file.txt" || aws.ToString(client.headInput.Bucket) != "bucket" {
		t.Fatal("delete or health request was not mapped")
	}
	signedURL, err := store.SignedURL(context.Background(), "docs/file.txt", time.Minute)
	if err != nil || signedURL != "https://signed.example.com/object" {
		t.Fatalf("sign S3 URL: %s %v", signedURL, err)
	}
}

// TestStoreMapsObjectExists 验证 S3 条件写入冲突映射为统一对象已存在错误。
func TestStoreMapsObjectExists(t *testing.T) {
	// 使用 Smithy 标准 API 错误模拟 S3 前置条件失败。
	client := &mockClient{putErr: &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "object exists"}}
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
