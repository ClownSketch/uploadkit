package uploadkit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingStore 统计 Put 次数并保存写入内容，供验收断言使用。
type countingStore struct {
	memoryStore
	putCount atomic.Int64 // putCount 成功进入 Put 的次数
}

// Put 记录调用次数后再写入内存对象。
func (s *countingStore) Put(ctx context.Context, object PutObject) (StoredObject, error) {
	s.putCount.Add(1)
	return s.memoryStore.Put(ctx, object)
}

// TestUploadSuccessPutsOnce 验证检查全部通过时 Store.Put 恰好一次且内容一致。
func TestUploadSuccessPutsOnce(t *testing.T) {
	store := &countingStore{}
	uploader, err := New(store, WithKeyGenerator(func(KeyInput) (string, error) {
		return "ok/file.txt", nil
	}))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	content := []byte("safe upload content")
	result, err := uploader.Upload(context.Background(), FromBytes("file.txt", content))
	if err != nil {
		t.Fatalf("upload file: %v", err)
	}
	if store.putCount.Load() != 1 {
		t.Fatalf("expected exactly one Put, got %d", store.putCount.Load())
	}
	if !bytes.Equal(store.objects[result.ObjectKey], content) {
		t.Fatal("stored content does not match inspected content")
	}
}

// TestBlockedInspectorPreventsPut 验证检查器阻塞期间不会提前成功或写入存储。
func TestBlockedInspectorPreventsPut(t *testing.T) {
	store := &countingStore{}
	started := make(chan struct{})
	release := make(chan struct{})
	uploader, err := New(store, WithInspector(InspectorFunc(func(ctx context.Context, file FileInfo, content io.Reader) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, uploadErr := uploader.UploadRequest(context.Background(), Request{
			Source: FromBytes("blocked.txt", []byte("blocked")),
			Policy: policy,
		})
		errCh <- uploadErr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inspector did not start")
	}
	if store.putCount.Load() != 0 {
		t.Fatalf("Put must stay zero while inspector is blocked, got %d", store.putCount.Load())
	}
	select {
	case uploadErr := <-errCh:
		t.Fatalf("upload returned before inspector release: %v", uploadErr)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if uploadErr := <-errCh; uploadErr != nil {
		t.Fatalf("upload after release: %v", uploadErr)
	}
	if store.putCount.Load() != 1 {
		t.Fatalf("expected one Put after release, got %d", store.putCount.Load())
	}
}

// TestInspectAndScanFailuresSkipPut 验证命中、拒绝、扫描故障、超时和取消都不会进入 Store.Put。
func TestInspectAndScanFailuresSkipPut(t *testing.T) {
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	tests := []struct {
		name       string
		options    []Option
		timeout    bool
		threat     bool
		incomplete bool
		reject     bool
	}{
		{
			name: "threat",
			options: []Option{WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
				return ScanResult{Threat: "TEST.Threat"}, nil
			}))},
			threat: true,
		},
		{
			name: "inspector reject",
			options: []Option{
				WithInspector(InspectorFunc(func(context.Context, FileInfo, io.Reader) error {
					return errors.New("business structure rejected")
				})),
				WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
					return ScanResult{Clean: true}, nil
				})),
			},
			reject: true,
		},
		{
			name: "scan incomplete",
			options: []Option{WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
				return ScanResult{}, errors.New("engine unavailable")
			}))},
			incomplete: true,
		},
		{
			name: "timeout",
			options: []Option{WithScanner(ScannerFunc(func(ctx context.Context, _ FileInfo, _ io.Reader) (ScanResult, error) {
				<-ctx.Done()
				return ScanResult{}, ctx.Err()
			}))},
			timeout: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &countingStore{}
			uploader, createErr := New(store, test.options...)
			if createErr != nil {
				t.Fatalf("create uploader: %v", createErr)
			}
			var uploadErr error
			if test.timeout {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				_, uploadErr = uploader.UploadRequest(ctx, Request{Source: FromBytes("a.txt", []byte("a")), Policy: policy})
			} else {
				_, uploadErr = uploader.UploadRequest(context.Background(), Request{Source: FromBytes("a.txt", []byte("a")), Policy: policy})
			}
			if store.putCount.Load() != 0 {
				t.Fatalf("Put must be zero, got %d", store.putCount.Load())
			}
			if test.threat && !errors.Is(uploadErr, ErrThreatDetected) {
				t.Fatalf("expected threat, got: %v", uploadErr)
			}
			if test.incomplete && !errors.Is(uploadErr, ErrScanIncomplete) {
				t.Fatalf("expected incomplete scan, got: %v", uploadErr)
			}
			if test.timeout && !errors.Is(uploadErr, context.DeadlineExceeded) {
				t.Fatalf("expected timeout, got: %v", uploadErr)
			}
			if test.reject && uploadErr == nil {
				t.Fatal("expected inspector rejection")
			}
			if test.threat && errors.Is(uploadErr, ErrScanIncomplete) {
				t.Fatal("threat must not be disguised as incomplete")
			}
			if test.incomplete && errors.Is(uploadErr, ErrThreatDetected) {
				t.Fatal("incomplete must not be disguised as threat")
			}
		})
	}
}

// TestRequestPolicyCannotDisableInstanceScan 验证请求覆盖 Policy 不能关闭实例强制扫描。
func TestRequestPolicyCannotDisableInstanceScan(t *testing.T) {
	store := &countingStore{}
	defaultPolicy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain", "image/png"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create default policy: %v", err)
	}
	scannerCalled := atomic.Bool{}
	uploader, err := New(store,
		WithDefaultPolicy(defaultPolicy),
		WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
			scannerCalled.Store(true)
			return ScanResult{Clean: true}, nil
		})),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	override, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: false,
	})
	if err != nil {
		t.Fatalf("create override policy: %v", err)
	}
	if _, err = uploader.UploadRequest(context.Background(), Request{
		Source: FromBytes("plain.txt", []byte("plain")),
		Policy: override,
	}); err != nil {
		t.Fatalf("upload with override policy: %v", err)
	}
	if !scannerCalled.Load() {
		t.Fatal("instance required scanner was skipped")
	}
	if store.putCount.Load() != 1 {
		t.Fatalf("expected one Put, got %d", store.putCount.Load())
	}
	if _, err = New(&countingStore{}, WithDefaultPolicy(defaultPolicy)); !errors.Is(err, ErrScannerRequired) {
		t.Fatalf("expected init failure without scanner, got: %v", err)
	}
}

// TestWithInspectorsAppendOnlyAndIsolated 验证请求追加检查器不替换实例检查器，且不串到并发请求。
func TestWithInspectorsAppendOnlyAndIsolated(t *testing.T) {
	store := &countingStore{}
	instanceHits := atomic.Int64{}
	requestHits := atomic.Int64{}
	uploader, err := New(store, WithInspector(InspectorFunc(func(context.Context, FileInfo, io.Reader) error {
		instanceHits.Add(1)
		return nil
	})))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{MaxFileSize: 1024, AllowedMIMETypes: []string{"text/plain"}})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	base := Request{Source: FromBytes("base.txt", []byte("base")), Policy: policy}
	extra := InspectorFunc(func(context.Context, FileInfo, io.Reader) error {
		requestHits.Add(1)
		return nil
	})
	withExtra := base.WithInspectors(extra)
	if len(base.inspectors) != 0 {
		t.Fatal("original request was mutated")
	}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		if _, uploadErr := uploader.UploadRequest(context.Background(), withExtra); uploadErr != nil {
			t.Errorf("upload with extra inspectors: %v", uploadErr)
		}
	}()
	go func() {
		defer wait.Done()
		if _, uploadErr := uploader.UploadRequest(context.Background(), base); uploadErr != nil {
			t.Errorf("upload base request: %v", uploadErr)
		}
	}()
	wait.Wait()
	if instanceHits.Load() != 2 {
		t.Fatalf("expected instance inspector twice, got %d", instanceHits.Load())
	}
	if requestHits.Load() != 1 {
		t.Fatalf("expected request inspector once, got %d", requestHits.Load())
	}
	if store.putCount.Load() != 2 {
		t.Fatalf("expected two puts, got %d", store.putCount.Load())
	}
}

// TestOtherUploadEntriesStillScan 验证简洁入口与批量入口都走同一检查路径。
func TestOtherUploadEntriesStillScan(t *testing.T) {
	store := &countingStore{}
	scans := atomic.Int64{}
	defaultPolicy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		MaxFiles:              4,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	uploader, err := New(store,
		WithDefaultPolicy(defaultPolicy),
		WithScanner(ScannerFunc(func(context.Context, FileInfo, io.Reader) (ScanResult, error) {
			scans.Add(1)
			return ScanResult{Clean: true}, nil
		})),
		WithKeyGenerator(func(input KeyInput) (string, error) {
			return "entry/" + input.OriginalName, nil
		}),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	if _, err = uploader.Upload(context.Background(), FromBytes("one.txt", []byte("one"))); err != nil {
		t.Fatalf("upload entry: %v", err)
	}
	batch, err := uploader.UploadMany(context.Background(), []Source{
		FromBytes("two.txt", []byte("two")),
		FromBytes("three.txt", []byte("three")),
	})
	if err != nil {
		t.Fatalf("batch upload: %v", err)
	}
	if batch.Succeeded != 2 {
		t.Fatalf("unexpected batch result: %+v", batch)
	}
	if scans.Load() != 3 {
		t.Fatalf("expected three scans, got %d", scans.Load())
	}
	if store.putCount.Load() != 3 {
		t.Fatalf("expected three puts, got %d", store.putCount.Load())
	}
}

// TestCanceledUploadCleansStageWithoutPut 验证取消时不写入存储。
func TestCanceledUploadCleansStageWithoutPut(t *testing.T) {
	store := &countingStore{}
	uploader, err := New(store, WithScanner(ScannerFunc(func(ctx context.Context, _ FileInfo, _ io.Reader) (ScanResult, error) {
		<-ctx.Done()
		return ScanResult{}, ctx.Err()
	})))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	policy, err := NewPolicy(PolicyOptions{
		MaxFileSize:           1024,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = uploader.UploadRequest(ctx, Request{Source: FromBytes("cancel.txt", []byte("cancel")), Policy: policy})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled upload, got: %v", err)
	}
	if store.putCount.Load() != 0 {
		t.Fatalf("Put must be zero after cancel, got %d", store.putCount.Load())
	}
}
