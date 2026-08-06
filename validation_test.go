package uploadkit

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateObjectKey 验证对象键不会被静默改写。
func TestValidateObjectKey(t *testing.T) {
	invalidKeys := []string{
		"",
		" leading.txt",
		"trailing.txt ",
		"folder\\file.txt",
		"folder//file.txt",
		"../file.txt",
		"folder/\nfile.txt",
		strings.Repeat("a", maxObjectKeySize+1),
	}
	for _, objectKey := range invalidKeys {
		if err := ValidateObjectKey(objectKey); !errors.Is(err, ErrInvalidObjectKey) {
			t.Fatalf("expected invalid object key %q, got: %v", objectKey, err)
		}
	}
	if err := ValidateObjectKey("用户/文件.txt"); err != nil {
		t.Fatalf("validate Unicode object key: %v", err)
	}
}

// TestNewValidatesTempDirectory 验证显式隔离目录在初始化阶段完成校验。
func TestNewValidatesTempDirectory(t *testing.T) {
	// 不存在的隔离目录必须立即返回错误。
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := New(&memoryStore{}, WithTempDir(missing)); err == nil {
		t.Fatal("expected missing temp directory error")
	}
	// 普通文件不能被当作隔离目录。
	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, []byte("content"), 0o600); err != nil {
		t.Fatalf("write temp path file: %v", err)
	}
	if _, err := New(&memoryStore{}, WithTempDir(filePath)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected non-directory temp path error, got: %v", err)
	}
	// 已存在的隔离目录必须可以正常初始化。
	if _, err := New(&memoryStore{}, WithTempDir(t.TempDir())); err != nil {
		t.Fatalf("create uploader with temp directory: %v", err)
	}
}

// TestNilFunctionAdapters 验证空扫描和检查函数不会引发运行期异常。
func TestNilFunctionAdapters(t *testing.T) {
	// scanner 保存一个接口非空但底层函数为空的扫描器。
	var scanner ScannerFunc
	// Uploader 必须在初始化阶段拒绝空扫描函数。
	if _, err := New(&memoryStore{}, WithScanner(scanner)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected nil scanner function error, got: %v", err)
	}
	// 直接调用空扫描函数也必须返回相同配置错误。
	if _, err := scanner.Scan(context.Background(), FileInfo{}, strings.NewReader("content")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected direct nil scanner function error, got: %v", err)
	}

	// inspector 保存一个接口非空但底层函数为空的检查器。
	var inspector InspectorFunc
	// Uploader 必须在初始化阶段拒绝空检查函数。
	if _, err := New(&memoryStore{}, WithInspector(inspector)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected nil inspector function error, got: %v", err)
	}
	// 直接调用空检查函数也必须返回相同配置错误。
	if err := inspector.Inspect(context.Background(), FileInfo{}, strings.NewReader("content")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected direct nil inspector function error, got: %v", err)
	}
}

// TestCleanObjectPrefix 验证目录前缀不会被静默改写到其他对象命名空间。
func TestCleanObjectPrefix(t *testing.T) {
	// 非规范路径和目录穿越必须直接拒绝。
	invalidPrefixes := []string{"tenant-a/../tenant-b", "tenant//files", "tenant/./files", "/tenant", `tenant\files`}
	for _, prefix := range invalidPrefixes {
		if _, err := cleanObjectPrefix(prefix); !errors.Is(err, ErrInvalidObjectKey) {
			t.Fatalf("expected invalid prefix %q, got: %v", prefix, err)
		}
	}
	// 常见的单个末尾分隔符可以作为目录书写形式使用。
	prefix, err := cleanObjectPrefix("tenant/files/")
	if err != nil || prefix != "tenant/files" {
		t.Fatalf("clean trailing separator: %q %v", prefix, err)
	}
}

// TestUploaderRejectsUnnormalizedObjectKey 验证上传器不会静默修正固定对象键。
func TestUploaderRejectsUnnormalizedObjectKey(t *testing.T) {
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	_, err = uploader.UploadRequest(context.Background(), Request{
		Source:    FromBytes("file.txt", []byte("content")),
		Policy:    policy,
		ObjectKey: " leading.txt",
	})
	if !errors.Is(err, ErrInvalidObjectKey) {
		t.Fatalf("expected invalid fixed key, got: %v", err)
	}
}

// TestPolicyRejectsNumericBoundary 验证大小和浮点边界不能绕过限制。
func TestPolicyRejectsNumericBoundary(t *testing.T) {
	tests := []PolicyOptions{
		{MaxFileSize: math.MaxInt64, AllowedMIMETypes: []string{"text/plain"}},
		{MaxFileSize: 1024, AllowedMIMETypes: []string{"application/zip"}, MaxArchiveExpandedBytes: math.MaxInt64},
		{MaxFileSize: 1024, AllowedMIMETypes: []string{"application/zip"}, MaxCompressionRatio: math.NaN()},
		{MaxFileSize: 1024, AllowedMIMETypes: []string{"application/zip"}, MaxCompressionRatio: math.Inf(1)},
	}
	for index, options := range tests {
		if _, err := NewPolicy(options); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("expected invalid numeric policy %d, got: %v", index, err)
		}
	}
}

// TestNormalizeMetadata 验证跨云元数据键值规则。
func TestNormalizeMetadata(t *testing.T) {
	metadata, err := normalizeMetadata(map[string]string{"Owner-ID": "tenant"})
	if err != nil || metadata["owner-id"] != "tenant" {
		t.Fatalf("normalize metadata: %+v %v", metadata, err)
	}
	invalidMetadata := []map[string]string{
		{"owner_id": "tenant"},
		{"owner": "line\nbreak"},
		{"Owner": "first", "owner": "second"},
	}
	for index, values := range invalidMetadata {
		if _, err = normalizeMetadata(values); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid metadata %d, got: %v", index, err)
		}
	}
}

// TestValidatePutObject 验证官方存储适配器使用一致的写入参数合同。
func TestValidatePutObject(t *testing.T) {
	// valid 保存一份完整有效的对象参数。
	valid := PutObject{
		Key:                "docs/file.txt",
		Body:               strings.NewReader("content"),
		Size:               7,
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
		Metadata:           map[string]string{"owner": "tenant"},
	}
	// 完整对象参数必须通过公共校验。
	if err := ValidatePutObject(valid); err != nil {
		t.Fatalf("validate complete object: %v", err)
	}
	// 空内容、非法大小、畸形类型和错误哈希都必须被拒绝。
	invalidObjects := []PutObject{
		{Key: valid.Key, Size: valid.Size, ContentType: valid.ContentType, ChecksumSHA256: valid.ChecksumSHA256},
		{Key: valid.Key, Body: valid.Body, Size: 0, ContentType: valid.ContentType, ChecksumSHA256: valid.ChecksumSHA256},
		{Key: valid.Key, Body: valid.Body, Size: valid.Size, ContentType: "invalid", ChecksumSHA256: valid.ChecksumSHA256},
		{Key: valid.Key, Body: valid.Body, Size: valid.Size, ContentType: "image/*", ContentDisposition: valid.ContentDisposition, ChecksumSHA256: valid.ChecksumSHA256},
		{Key: valid.Key, Body: valid.Body, Size: valid.Size, ContentType: valid.ContentType, ChecksumSHA256: "invalid"},
		{Key: valid.Key, Body: valid.Body, Size: valid.Size, ContentType: valid.ContentType, ContentDisposition: valid.ContentDisposition, ChecksumSHA256: valid.ChecksumSHA256, Metadata: map[string]string{"Owner": "tenant"}},
	}
	for index, object := range invalidObjects {
		if err := ValidatePutObject(object); err == nil {
			t.Fatalf("expected invalid object %d", index)
		}
	}
}
