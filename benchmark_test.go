package uploadkit

import (
	"context"
	"io"
	"testing"
)

// discardStore 读取并丢弃基准测试对象。
type discardStore struct{}

// Put 消费测试对象。
func (s *discardStore) Put(ctx context.Context, object PutObject) (StoredObject, error) {
	if _, err := io.Copy(io.Discard, object.Body); err != nil {
		return StoredObject{}, err
	}
	return StoredObject{}, nil
}

// Delete 实现存储删除契约。
func (s *discardStore) Delete(ctx context.Context, objectKey string) error {
	return nil
}

// BenchmarkUploaderUpload 测量包含隔离、识别、哈希和存储的完整上传开销。
func BenchmarkUploaderUpload(b *testing.B) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      64 << 10,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		b.Fatalf("create policy: %v", err)
	}
	uploader, err := New(&discardStore{}, WithMaxConcurrency(32))
	if err != nil {
		b.Fatalf("create uploader: %v", err)
	}
	content := make([]byte, 16<<10)
	for index := range content {
		content[index] = 'a'
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_, uploadErr := uploader.UploadRequest(context.Background(), Request{
			Source: FromBytes("benchmark.txt", content),
			Policy: policy,
		})
		if uploadErr != nil {
			b.Fatalf("upload file: %v", uploadErr)
		}
	}
}

// BenchmarkUploaderUploadParallel 测量并行完整上传开销。
func BenchmarkUploaderUploadParallel(b *testing.B) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:      64 << 10,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		b.Fatalf("create policy: %v", err)
	}
	uploader, err := New(&discardStore{}, WithMaxConcurrency(32))
	if err != nil {
		b.Fatalf("create uploader: %v", err)
	}
	content := make([]byte, 16<<10)
	for index := range content {
		content[index] = 'a'
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			_, uploadErr := uploader.UploadRequest(context.Background(), Request{
				Source: FromBytes("benchmark.txt", content),
				Policy: policy,
			})
			if uploadErr != nil {
				b.Errorf("upload file: %v", uploadErr)
				return
			}
		}
	})
}
