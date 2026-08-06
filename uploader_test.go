package uploadkit

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoryStore 保存测试上传结果并统计并行操作数。
type memoryStore struct {
	mutex      sync.Mutex        // mutex 保护对象集合
	objects    map[string][]byte // objects 已保存对象
	active     atomic.Int64      // active 当前写入数
	maxActive  atomic.Int64      // maxActive 最大并行写入数
	writeDelay time.Duration     // writeDelay 模拟存储耗时
	putErr     error             // putErr 模拟存储错误
}

// capableStore 为测试存储补充健康检查和签名地址能力。
type capableStore struct {
	memoryStore
}

// Ping 返回测试健康状态。
func (s *capableStore) Ping(ctx context.Context) error {
	return ctx.Err()
}

// SignedURL 返回测试签名地址。
func (s *capableStore) SignedURL(ctx context.Context, objectKey string, expires time.Duration) (string, error) {
	return "https://signed.example.com/" + objectKey, ctx.Err()
}

// Put 保存测试对象。
// @param ctx context.Context 调用上下文
// @param object PutObject 待保存对象
// @return result StoredObject 存储结果
// @return err error 读取错误
func (s *memoryStore) Put(ctx context.Context, object PutObject) (result StoredObject, err error) {
	// 配置了固定错误时不消费对象内容。
	if s.putErr != nil {
		return StoredObject{}, s.putErr
	}
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		maximum := s.maxActive.Load()
		if active <= maximum || s.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	if s.writeDelay > 0 {
		select {
		case <-time.After(s.writeDelay):
		case <-ctx.Done():
			return StoredObject{}, ctx.Err()
		}
	}
	content, err := io.ReadAll(object.Body)
	if err != nil {
		return StoredObject{}, err
	}
	s.mutex.Lock()
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	s.objects[object.Key] = content
	s.mutex.Unlock()
	return StoredObject{ETag: object.ChecksumSHA256}, nil
}

// failingCloseReader 模拟读取成功但关闭失败的来源。
type failingCloseReader struct {
	*strings.Reader // Reader 提供测试内容
}

// Close 返回固定关闭错误。
// @return err error 关闭错误
func (r *failingCloseReader) Close() error {
	// 返回可识别错误，用于验证隔离文件收尾语义。
	return errors.New("close source")
}

// Delete 删除测试对象。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @return err error 始终为空
func (s *memoryStore) Delete(ctx context.Context, objectKey string) error {
	s.mutex.Lock()
	delete(s.objects, objectKey)
	s.mutex.Unlock()
	return nil
}

// TestUploaderUpload 验证来源隔离、检查、扫描和存储完整闭环。
func TestUploaderUpload(t *testing.T) {
	store := &memoryStore{}
	scannerCalled := false
	uploader, err := New(
		store,
		WithKeyGenerator(func(input KeyInput) (string, error) {
			return "avatar/test.png", nil
		}),
		WithScanner(ScannerFunc(func(ctx context.Context, file FileInfo, content io.Reader) (ScanResult, error) {
			scannerCalled = true
			if file.MIMEType != "image/png" {
				t.Fatalf("unexpected MIME type: %s", file.MIMEType)
			}
			return ScanResult{Clean: true}, nil
		})),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1 << 20,
		AllowedMIMETypes:      []string{"image/png"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	content := testPNG(t, 2, 2)
	result, err := uploader.UploadRequest(context.Background(), Request{
		Source:   FromBytes("avatar.png", content),
		Policy:   policy,
		Metadata: map[string]string{"owner": "tenant"},
	})
	if err != nil {
		t.Fatalf("upload file: %v", err)
	}
	if !scannerCalled {
		t.Fatal("scanner was not called")
	}
	if result.ObjectKey != "avatar/test.png" || result.Size != int64(len(content)) || result.MIMEType != "image/png" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !bytes.Equal(store.objects[result.ObjectKey], content) {
		t.Fatal("stored content does not match source")
	}
}

// TestUploaderObjectOperations 验证固定对象键和统一对象操作入口。
func TestUploaderObjectOperations(t *testing.T) {
	store := &capableStore{}
	uploader, err := New(store, WithKeyGenerator(func(input KeyInput) (string, error) {
		return "", errors.New("key generator should not be called")
	}))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	result, err := uploader.UploadRequest(context.Background(), Request{
		Source:    FromBytes("fixed.txt", []byte("fixed")),
		Policy:    policy,
		ObjectKey: "fixed/object.txt",
	})
	if err != nil || result.ObjectKey != "fixed/object.txt" {
		t.Fatalf("upload fixed object: %+v %v", result, err)
	}
	if err = uploader.Ping(context.Background()); err != nil {
		t.Fatalf("ping uploader: %v", err)
	}
	signedURL, err := uploader.SignedURL(context.Background(), result.ObjectKey, time.Minute)
	if err != nil || signedURL != "https://signed.example.com/fixed/object.txt" {
		t.Fatalf("sign object URL: %s %v", signedURL, err)
	}
	if err = uploader.Delete(context.Background(), result.ObjectKey); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	plainUploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create plain uploader: %v", err)
	}
	if _, err = plainUploader.SignedURL(context.Background(), result.ObjectKey, time.Minute); !errors.Is(err, ErrSignedURLUnsupported) {
		t.Fatalf("expected unsupported signed URL, got: %v", err)
	}
	if err = plainUploader.Ping(context.Background()); !errors.Is(err, ErrHealthCheckUnsupported) {
		t.Fatalf("expected unsupported health check, got: %v", err)
	}
}

// TestUploaderRejectsConflictingObjectLocation 验证固定对象键不会静默忽略目录前缀。
func TestUploaderRejectsConflictingObjectLocation(t *testing.T) {
	// 创建最小内存存储上传器。
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 创建文本文件策略。
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 同时指定固定键和前缀必须返回明确配置错误。
	_, err = uploader.UploadRequest(context.Background(), Request{
		Source:    FromBytes("file.txt", []byte("content")),
		Policy:    policy,
		ObjectKey: "fixed/file.txt",
		Prefix:    "tenant",
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected conflicting object location error, got: %v", err)
	}
}

// TestStageSourceRejectsInvalidImplementations 验证自定义来源不能返回非法大小或空读取流。
func TestStageSourceRejectsInvalidImplementations(t *testing.T) {
	// 创建可用的文本策略供隔离阶段使用。
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 声明大小小于 -1 必须在打开前被拒绝。
	invalidSize := &source{name: "file.txt", size: -2, open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("content")), nil
	}}
	if _, err = stageSource(context.Background(), invalidSize, policy, t.TempDir()); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("expected invalid source size, got: %v", err)
	}
	// 成功打开但返回空流也必须被拒绝。
	nilReader := &source{name: "file.txt", size: 7, open: func(context.Context) (io.ReadCloser, error) {
		return nil, nil
	}}
	if _, err = stageSource(context.Background(), nilReader, policy, t.TempDir()); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("expected nil opened reader error, got: %v", err)
	}
}

// TestStageSourceCloseFailureCleansTemporaryFile 验证来源关闭失败时不会留下可提交的隔离文件。
func TestStageSourceCloseFailureCleansTemporaryFile(t *testing.T) {
	// 创建独立隔离目录，便于检查残留文件。
	tempDir := t.TempDir()
	// 创建可用的文本策略。
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 使用读取正常、关闭失败的测试来源。
	closeFailure := &source{name: "file.txt", size: 7, open: func(context.Context) (io.ReadCloser, error) {
		return &failingCloseReader{Reader: strings.NewReader("content")}, nil
	}}
	// 关闭错误必须阻止隔离结果继续上传。
	if _, err = stageSource(context.Background(), closeFailure, policy, tempDir); err == nil || !strings.Contains(err.Error(), "close source") {
		t.Fatalf("expected source close error, got: %v", err)
	}
	// 隔离目录中不能留下临时文件。
	entries, readErr := os.ReadDir(tempDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("temporary files were not cleaned: entries=%d err=%v", len(entries), readErr)
	}
}

// TestPolicyMIMEWildcard 验证 MIME 主类型通配规则。
func TestPolicyMIMEWildcard(t *testing.T) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      1 << 20,
		AllowedMIMETypes: []string{"image/*"},
	})
	if err != nil {
		t.Fatalf("create wildcard policy: %v", err)
	}
	if err = policy.validateType("avatar.png", "image/png"); err != nil {
		t.Fatalf("validate wildcard MIME: %v", err)
	}
	if err = policy.validateType("report.pdf", "application/pdf"); !errors.Is(err, ErrMIMETypeNotAllowed) {
		t.Fatalf("expected MIME rejection, got: %v", err)
	}
	invalidMIMETypes := []string{"image/p*", "/*", "text", "text/", "text/plain/extra", "text/(plain)"}
	for _, mimeType := range invalidMIMETypes {
		if _, err = NewPolicy(PolicyOptions{MaxFileSize: 1, AllowedMIMETypes: []string{mimeType}}); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("expected invalid MIME rule %q, got: %v", mimeType, err)
		}
	}
}

// TestPolicyDeniedMIMEWins 验证拒绝规则始终优先于允许规则。
func TestPolicyDeniedMIMEWins(t *testing.T) {
	// 允许所有类型，但明确拒绝图片主类型。
	policy, err := NewPolicy(PolicyOptions{
		AllowedMIMETypes: []string{"*/*"},
		DeniedMIMETypes:  []string{"image/*"},
	})
	if err != nil {
		t.Fatalf("create deny policy: %v", err)
	}
	// 图片命中拒绝规则后不能被全量允许规则放行。
	if err = policy.validateType("avatar.png", "image/png"); !errors.Is(err, ErrMIMETypeNotAllowed) {
		t.Fatalf("expected denied MIME rejection, got: %v", err)
	}
	// 未命中拒绝规则的文本类型仍可正常通过。
	if err = policy.validateType("readme.txt", "text/plain"); err != nil {
		t.Fatalf("validate allowed MIME: %v", err)
	}
}

// TestUploaderDefaultPolicy 验证默认上传策略和单次请求策略的职责边界。
func TestUploaderDefaultPolicy(t *testing.T) {
	// 创建使用内置保守策略的上传器。
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 文本文件属于默认允许类型，可使用最简入口上传。
	if _, err = uploader.Upload(context.Background(), FromBytes("readme.txt", []byte("content"))); err != nil {
		t.Fatalf("upload with default policy: %v", err)
	}
	// ZIP 不在默认允许列表中，主项目未放行时必须拒绝。
	archive := testZIP(t, map[string][]byte{"readme.txt": []byte("content")})
	if _, err = uploader.Upload(context.Background(), FromBytes("archive.zip", archive)); !errors.Is(err, ErrMIMETypeNotAllowed) {
		t.Fatalf("expected default ZIP rejection, got: %v", err)
	}
	// 主项目显式允许 ZIP 后，可通过进阶请求覆盖本次策略。
	archivePolicy, err := NewPolicy(PolicyOptions{AllowedMIMETypes: []string{"application/zip"}})
	if err != nil {
		t.Fatalf("create archive policy: %v", err)
	}
	// 主项目也可以把自定义策略设置为当前上传器的长期默认策略。
	archiveUploader, err := New(&memoryStore{}, WithDefaultPolicy(archivePolicy))
	if err != nil {
		t.Fatalf("create archive uploader: %v", err)
	}
	// 最简入口必须使用初始化时配置的主项目默认策略。
	if _, err = archiveUploader.Upload(context.Background(), FromBytes("archive.zip", archive)); err != nil {
		t.Fatalf("upload with custom default policy: %v", err)
	}
	if _, err = uploader.UploadRequest(context.Background(), Request{
		Source: FromBytes("archive.zip", archive),
		Policy: archivePolicy,
		Prefix: "archives",
	}); err != nil {
		t.Fatalf("upload explicitly allowed ZIP: %v", err)
	}
}

// TestNilUploaderUploadMany 验证空上传器调用批量入口时返回明确错误。
func TestNilUploaderUploadMany(t *testing.T) {
	// 空接收者不能因为读取默认策略而触发运行时异常。
	var uploader *Uploader
	// 批量入口应与其他对象操作保持一致的空存储错误语义。
	if _, err := uploader.UploadMany(context.Background(), nil); !errors.Is(err, ErrNilStore) {
		t.Fatalf("expected nil store error, got: %v", err)
	}
}

// TestUploaderRejectsUnsafeInput 验证常见伪装和安全门禁。
func TestUploaderRejectsUnsafeInput(t *testing.T) {
	textPolicy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      8,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create text policy: %v", err)
	}
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	tests := []struct {
		name   string
		source Source
		policy Policy
		target error
	}{
		{name: "actual size", source: FromBytes("large.txt", []byte("123456789")), policy: textPolicy, target: ErrFileTooLarge},
		{name: "extension mismatch", source: FromBytes("plain.png", []byte("plain")), policy: textPolicy, target: ErrExtensionMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, uploadErr := uploader.UploadRequest(context.Background(), Request{Source: test.source, Policy: test.policy})
			if !errors.Is(uploadErr, test.target) {
				t.Fatalf("expected %v, got %v", test.target, uploadErr)
			}
		})
	}
	requiredPolicy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create scanner policy: %v", err)
	}
	_, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("plain.txt", []byte("plain")), Policy: requiredPolicy})
	if !errors.Is(err, ErrScannerRequired) {
		t.Fatalf("expected scanner requirement, got: %v", err)
	}
	threatUploader, err := New(&memoryStore{}, WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
		return ScanResult{Threat: "EICAR-Test-Signature"}, nil
	})))
	if err != nil {
		t.Fatalf("create threat uploader: %v", err)
	}
	_, err = threatUploader.UploadRequest(context.Background(), Request{Source: FromBytes("plain.txt", []byte("plain")), Policy: requiredPolicy})
	if !errors.Is(err, ErrThreatDetected) {
		t.Fatalf("expected threat rejection, got: %v", err)
	}
}

// TestInspectSVG 验证 SVG 主动内容拦截。
func TestInspectSVG(t *testing.T) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      4096,
		AllowedMIMETypes: []string{"image/svg+xml"},
	})
	if err != nil {
		t.Fatalf("create SVG policy: %v", err)
	}
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	valid := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>`)
	if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("safe.svg", valid), Policy: policy}); err != nil {
		t.Fatalf("upload safe SVG: %v", err)
	}
	unsafeDocuments := [][]byte{
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(https://example.com/style.css)</style></svg>`),
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="href" to="https://example.com/file"/></svg>`),
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://example.com/image)"/></svg>`),
		[]byte(`<?xml version="1.0"?><?xml-stylesheet href="https://example.com/style.css"?><svg xmlns="http://www.w3.org/2000/svg"/>`),
	}
	for index, unsafe := range unsafeDocuments {
		if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("unsafe.svg", unsafe), Policy: policy}); !errors.Is(err, ErrUnsafeSVG) {
			t.Fatalf("expected unsafe SVG rejection %d, got: %v", index, err)
		}
	}
}

// TestInspectZIP 验证 ZIP 路径穿越、嵌套归档和解压上限。
func TestInspectZIP(t *testing.T) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:             1 << 20,
		AllowedMIMETypes:        []string{"application/zip"},
		MaxArchiveFiles:         10,
		MaxArchiveExpandedBytes: 1024,
		MaxCompressionRatio:     20,
	})
	if err != nil {
		t.Fatalf("create ZIP policy: %v", err)
	}
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "path traversal", content: testZIP(t, map[string][]byte{"../evil.txt": []byte("evil")})},
		{name: "windows volume path", content: testZIP(t, map[string][]byte{"C:/outside.txt": []byte("evil")})},
		{name: "windows data stream", content: testZIP(t, map[string][]byte{"docs/file.txt:stream": []byte("evil")})},
		{name: "normalized traversal", content: testZIP(t, map[string][]byte{"docs/../evil.txt": []byte("evil")})},
		{name: "nested archive", content: testZIP(t, map[string][]byte{"inside.zip": []byte("zip")})},
		{name: "disguised nested archive", content: testZIP(t, map[string][]byte{"inside.txt": testZIP(t, map[string][]byte{"file.txt": []byte("nested")})})},
		{name: "expanded limit", content: testZIP(t, map[string][]byte{"large.txt": bytes.Repeat([]byte("a"), 2048)})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, uploadErr := uploader.UploadRequest(context.Background(), Request{Source: FromBytes("archive.zip", test.content), Policy: policy})
			if !errors.Is(uploadErr, ErrUnsafeArchive) {
				t.Fatalf("expected unsafe archive, got: %v", uploadErr)
			}
		})
	}
	safe := testZIP(t, map[string][]byte{"docs/readme.txt": []byte("hello")})
	if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("safe.zip", safe), Policy: policy}); err != nil {
		t.Fatalf("upload safe ZIP: %v", err)
	}
}

// TestInspectOfficeZIPContainer 验证 Office 文件同样执行 ZIP 解压边界检查。
func TestInspectOfficeZIPContainer(t *testing.T) {
	// 创建允许 DOCX 但限制解压总量的策略。
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:             1 << 20,
		AllowedMIMETypes:        []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveFiles:         10,
		MaxArchiveExpandedBytes: 1024,
		MaxCompressionRatio:     20,
	})
	if err != nil {
		t.Fatalf("create DOCX policy: %v", err)
	}
	// 创建使用内存存储的上传器。
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// safeDOCX 包含 MIME 识别需要的标准目录和小型正文。
	safeDOCX := testOrderedZIP(t, []testZIPEntry{
		{name: "[Content_Types].xml", content: []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`)},
		{name: "word/document.xml", content: []byte(`<document/>`)},
	})
	// 合法 Office 容器应通过结构检查。
	if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("safe.docx", safeDOCX), Policy: policy}); err != nil {
		t.Fatalf("upload safe DOCX: %v", err)
	}
	// oversizedDOCX 外层类型合法，但内部解压大小超过策略。
	oversizedDOCX := testOrderedZIP(t, []testZIPEntry{
		{name: "[Content_Types].xml", content: []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`)},
		{name: "word/document.xml", content: bytes.Repeat([]byte("a"), 2048)},
	})
	// ZIP 容器限制必须覆盖 DOCX，不能只保护普通 .zip 文件。
	if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("large.docx", oversizedDOCX), Policy: policy}); !errors.Is(err, ErrUnsafeArchive) {
		t.Fatalf("expected unsafe DOCX rejection, got: %v", err)
	}
}

// TestInspectorsReceiveReadOnlyContent 验证扩展检查器不能修改已经完成校验的隔离文件。
func TestInspectorsReceiveReadOnlyContent(t *testing.T) {
	// writable 标记检查器或扫描器是否获得写入能力。
	writable := false
	// 创建同时注册检查器和扫描器的上传器。
	uploader, err := New(
		&memoryStore{},
		WithInspector(InspectorFunc(func(ctx context.Context, file FileInfo, content io.Reader) error {
			// 检查器只能读取内容，不能获得底层文件写入接口。
			_, writable = content.(io.Writer)
			return ctx.Err()
		})),
		WithScanner(ScannerFunc(func(ctx context.Context, file FileInfo, content io.Reader) (ScanResult, error) {
			// 扫描器同样只能读取独立内容视图。
			if _, canWrite := content.(io.Writer); canWrite {
				writable = true
			}
			return ScanResult{Clean: true}, ctx.Err()
		})),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 创建要求扫描器执行的文本策略。
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 执行完整上传流程。
	if _, err = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("file.txt", []byte("content")), Policy: policy}); err != nil {
		t.Fatalf("upload inspected file: %v", err)
	}
	// 任一扩展获得写入能力都表示隔离边界失效。
	if writable {
		t.Fatal("inspector or scanner received writable staged content")
	}
}

// TestUploadBatchPreservesOrderAndLimitsConcurrency 验证批量顺序和并发上限。
func TestUploadBatchPreservesOrderAndLimitsConcurrency(t *testing.T) {
	store := &memoryStore{writeDelay: 15 * time.Millisecond}
	uploader, err := New(store,
		WithMaxConcurrency(3),
		WithKeyGenerator(func(input KeyInput) (string, error) {
			return path.Join("batch", input.OriginalName), nil
		}),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      1024,
		MaxFiles:         12,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	sources := make([]Source, 12)
	for index := range sources {
		fileName := "file-" + string(rune('a'+index)) + ".txt"
		sources[index] = FromBytes(fileName, []byte(fileName))
	}
	result, err := uploader.UploadManyWithPolicy(context.Background(), sources, policy)
	if err != nil {
		t.Fatalf("upload batch: %v", err)
	}
	if result.Succeeded != len(sources) || result.Failed != 0 {
		t.Fatalf("unexpected batch counts: %+v", result)
	}
	for index, item := range result.Items {
		expectedName := "batch/file-" + string(rune('a'+index)) + ".txt"
		if item.Index != index || item.Result.ObjectKey != expectedName {
			t.Fatalf("batch order changed at %d: %+v", index, item)
		}
	}
	if maximum := store.maxActive.Load(); maximum < 2 || maximum > 3 {
		t.Fatalf("unexpected maximum concurrency: %d", maximum)
	}
}

// TestUploadBatchReportsPartialFailure 验证批量部分失败不会被顶层返回值误报为成功。
func TestUploadBatchReportsPartialFailure(t *testing.T) {
	// 创建使用默认并发设置的内存上传器。
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 创建允许当前批次大小的文本策略。
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      1024,
		MaxFiles:         3,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 中间项目使用空文件制造单项失败。
	requests := []Request{
		{Source: FromBytes("first.txt", []byte("first")), Policy: policy},
		{Source: FromBytes("empty.txt", nil), Policy: policy},
		{Source: FromBytes("third.txt", []byte("third")), Policy: policy},
	}
	// 执行批量上传并保留完整逐项结果。
	result, err := uploader.UploadBatch(context.Background(), requests)
	// 顶层错误必须明确表示批量中存在失败项目。
	if !errors.Is(err, ErrBatchFailed) {
		t.Fatalf("expected batch failure, got: %v", err)
	}
	// 成功、失败数量和项目顺序必须准确。
	if result.Succeeded != 2 || result.Failed != 1 || len(result.Items) != len(requests) {
		t.Fatalf("unexpected batch result: %+v", result)
	}
	// 中间项目必须保留具体的空文件错误。
	if result.Items[1].Index != 1 || !errors.Is(result.Items[1].Err, ErrEmptyFile) {
		t.Fatalf("unexpected failed item: %+v", result.Items[1])
	}
}

// TestUploadBatchCancellationPreservesItems 验证取消后的批量结果仍保留完整下标和失败原因。
func TestUploadBatchCancellationPreservesItems(t *testing.T) {
	// 创建使用默认并发设置的内存上传器。
	uploader, err := New(&memoryStore{})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 创建允许当前批次大小的文本策略。
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      1024,
		MaxFiles:         3,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 创建并立即取消批量上下文。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// 构建三个不会进入存储阶段的请求。
	requests := []Request{
		{Source: FromBytes("first.txt", []byte("first")), Policy: policy},
		{Source: FromBytes("second.txt", []byte("second")), Policy: policy},
		{Source: FromBytes("third.txt", []byte("third")), Policy: policy},
	}
	// 执行取消后的批量上传。
	result, err := uploader.UploadBatch(ctx, requests)
	// 顶层错误必须保持标准上下文取消语义。
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got: %v", err)
	}
	// 所有未执行项目都必须计入失败并保留下标。
	if result.Succeeded != 0 || result.Failed != len(requests) || len(result.Items) != len(requests) {
		t.Fatalf("unexpected canceled batch result: %+v", result)
	}
	for index, item := range result.Items {
		if item.Index != index || !errors.Is(item.Err, context.Canceled) {
			t.Fatalf("unexpected canceled item %d: %+v", index, item)
		}
	}
}

// TestUploadBatchPreservesStoreContextError 验证存储层独立返回的上下文错误不会在顶层丢失。
func TestUploadBatchPreservesStoreContextError(t *testing.T) {
	// 创建固定返回取消错误的存储适配器。
	uploader, err := New(&memoryStore{putErr: context.Canceled})
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	// 创建允许两个文件的文本策略。
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      1024,
		MaxFiles:         2,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// 使用未取消的调用上下文执行批量上传。
	result, err := uploader.UploadManyWithPolicy(context.Background(), []Source{
		FromBytes("first.txt", []byte("first")),
		FromBytes("second.txt", []byte("second")),
	}, policy)
	// 顶层错误必须保留存储层返回的取消语义。
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected store context error, got: %v", err)
	}
	// 两个项目都必须保留各自的执行错误。
	if result.Failed != 2 || result.Succeeded != 0 {
		t.Fatalf("unexpected batch result: %+v", result)
	}
}

// testPNG 创建指定尺寸的有效 PNG。
// @param t *testing.T 测试上下文
// @param width int 图片宽度
// @param height int 图片高度
// @return result []byte PNG 内容
func testPNG(t *testing.T, width int, height int) []byte {
	t.Helper()
	imageData := image.NewRGBA(image.Rect(0, 0, width, height))
	imageData.Set(0, 0, color.RGBA{R: 255, A: 255})
	buffer := bytes.NewBuffer(nil)
	if err := png.Encode(buffer, imageData); err != nil {
		t.Fatalf("encode PNG: %v", err)
	}
	return buffer.Bytes()
}

// testZIP 创建包含指定条目的 ZIP。
// @param t *testing.T 测试上下文
// @param files map[string][]byte 条目内容
// @return result []byte ZIP 内容
func testZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	buffer := bytes.NewBuffer(nil)
	writer := zip.NewWriter(buffer)
	for fileName, content := range files {
		entry, err := writer.Create(fileName)
		if err != nil {
			t.Fatalf("create ZIP entry: %v", err)
		}
		if _, err = io.Copy(entry, strings.NewReader(string(content))); err != nil {
			t.Fatalf("write ZIP entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP: %v", err)
	}
	return buffer.Bytes()
}

// testZIPEntry 描述需要保持写入顺序的 ZIP 测试条目。
type testZIPEntry struct {
	name    string // name 条目名称
	content []byte // content 条目内容
}

// testOrderedZIP 按指定顺序创建 ZIP，便于构造依赖目录顺序识别的容器格式。
// @param t *testing.T 测试上下文
// @param files []testZIPEntry 有序条目
// @return result []byte ZIP 内容
func testOrderedZIP(t *testing.T, files []testZIPEntry) []byte {
	// 标记当前方法为测试辅助方法。
	t.Helper()
	// buffer 保存生成的 ZIP 内容。
	buffer := bytes.NewBuffer(nil)
	// writer 负责写入 ZIP 中央目录和条目。
	writer := zip.NewWriter(buffer)
	// 按调用方顺序创建每个条目。
	for _, file := range files {
		entry, err := writer.Create(file.name)
		if err != nil {
			t.Fatalf("create ordered ZIP entry: %v", err)
		}
		if _, err = entry.Write(file.content); err != nil {
			t.Fatalf("write ordered ZIP entry: %v", err)
		}
	}
	// 完成中央目录写入。
	if err := writer.Close(); err != nil {
		t.Fatalf("close ordered ZIP: %v", err)
	}
	// 返回完整 ZIP 字节。
	return buffer.Bytes()
}
