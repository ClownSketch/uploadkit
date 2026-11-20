package uploadkit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ClownSketch/uploadkit"
	"github.com/ClownSketch/uploadkit/scanner/offline"
)

// countingStore 统计 Put 次数并保存写入内容。
type countingStore struct {
	mutex    sync.Mutex
	objects  map[string][]byte
	putCount atomic.Int64
}

// Put 记录调用次数后保存对象。
func (s *countingStore) Put(ctx context.Context, object uploadkit.PutObject) (uploadkit.StoredObject, error) {
	s.putCount.Add(1)
	content, err := io.ReadAll(object.Body)
	if err != nil {
		return uploadkit.StoredObject{}, err
	}
	s.mutex.Lock()
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	s.objects[object.Key] = content
	s.mutex.Unlock()
	return uploadkit.StoredObject{ETag: object.ChecksumSHA256}, nil
}

// Delete 删除测试对象。
func (s *countingStore) Delete(ctx context.Context, objectKey string) error {
	s.mutex.Lock()
	delete(s.objects, objectKey)
	s.mutex.Unlock()
	return nil
}

// testJPEG 创建无害的最小 JPEG 样本。
func testJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buffer.Bytes()
}

// newOfflineUploader 使用给定规则包装配强制扫描上传器。
func newOfflineUploader(t *testing.T, store *countingStore, pack offline.RulePack) *uploadkit.Uploader {
	t.Helper()
	scanner, err := offline.New(offline.Config{RulePack: pack, RulePackDigest: "test"})
	if err != nil {
		t.Fatalf("create offline scanner: %v", err)
	}
	policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
		MaxFileSize:           1 << 20,
		AllowedMIMETypes:      []string{"image/jpeg"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	uploader, err := uploadkit.New(store,
		uploadkit.WithDefaultPolicy(policy),
		uploadkit.WithScanner(scanner),
		uploadkit.WithKeyGenerator(func(uploadkit.KeyInput) (string, error) { return "offline/test.jpg", nil }),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	return uploader
}

// TestUploadRequestNoApplicableRulesIsIncomplete 验证 JPEG 无适用规则时阻断写入。
func TestUploadRequestNoApplicableRulesIsIncomplete(t *testing.T) {
	store := &countingStore{}
	uploader := newOfflineUploader(t, store, offline.RulePack{
		Version: "mime-pdf-only",
		Rules: []offline.Rule{{
			ID:     "pdf.hash.only",
			Kind:   "sha256",
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			MIME:   []string{"application/pdf"},
			Threat: "TEST.PDF.Only",
		}},
	})
	_, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
		Source: uploadkit.FromBytes("photo.jpg", testJPEG(t)),
	})
	if !errors.Is(err, uploadkit.ErrScanIncomplete) {
		t.Fatalf("expected incomplete scan, got: %v", err)
	}
	if errors.Is(err, uploadkit.ErrThreatDetected) {
		t.Fatal("missing applicable rules must not look like a threat hit")
	}
	if store.putCount.Load() != 0 {
		t.Fatalf("Put must be zero, got %d", store.putCount.Load())
	}
}

// TestUploadRequestHashOnlyMissSucceeds 验证仅有适用摘要规则且未命中时可成功上传。
func TestUploadRequestHashOnlyMissSucceeds(t *testing.T) {
	store := &countingStore{}
	content := testJPEG(t)
	uploader := newOfflineUploader(t, store, offline.RulePack{
		Version: "jpeg-hash-only",
		Rules: []offline.Rule{{
			ID:     "jpeg.hash.miss",
			Kind:   "sha256",
			SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			MIME:   []string{"image/jpeg"},
			Threat: "TEST.JPEG.Hash",
		}},
	})
	result, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
		Source: uploadkit.FromBytes("photo.jpg", content),
	})
	if err != nil {
		t.Fatalf("hash-only miss should succeed: %v", err)
	}
	if store.putCount.Load() != 1 {
		t.Fatalf("expected one Put, got %d", store.putCount.Load())
	}
	if !bytes.Equal(store.objects[result.ObjectKey], content) {
		t.Fatal("stored content mismatch")
	}
}

// TestUploadRequestApplicableRuleHitsThreat 验证适用摘要或字节规则命中时拒绝写入。
func TestUploadRequestApplicableRuleHitsThreat(t *testing.T) {
	content := testJPEG(t)
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])

	t.Run("hash hit", func(t *testing.T) {
		store := &countingStore{}
		uploader := newOfflineUploader(t, store, offline.RulePack{
			Version: "jpeg-hash-hit",
			Rules: []offline.Rule{{
				ID:     "jpeg.hash.hit",
				Kind:   "sha256",
				SHA256: digest,
				MIME:   []string{"image/jpeg"},
				Threat: "TEST.JPEG.HashHit",
			}},
		})
		_, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
			Source: uploadkit.FromBytes("photo.jpg", content),
		})
		if !errors.Is(err, uploadkit.ErrThreatDetected) {
			t.Fatalf("expected threat, got: %v", err)
		}
		if store.putCount.Load() != 0 {
			t.Fatalf("Put must be zero, got %d", store.putCount.Load())
		}
	})

	t.Run("bytes hit after hash miss", func(t *testing.T) {
		store := &countingStore{}
		uploader := newOfflineUploader(t, store, offline.RulePack{
			Version: "jpeg-bytes-hit",
			Rules: []offline.Rule{
				{
					ID:     "jpeg.hash.miss",
					Kind:   "sha256",
					SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					MIME:   []string{"image/jpeg"},
					Threat: "TEST.JPEG.HashMiss",
				},
				{
					ID:      "jpeg.bytes.hit",
					Kind:    "bytes",
					Pattern: hex.EncodeToString(content[:16]),
					MIME:    []string{"image/jpeg"},
					Threat:  "TEST.JPEG.BytesHit",
				},
			},
		})
		_, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
			Source: uploadkit.FromBytes("photo.jpg", content),
		})
		if !errors.Is(err, uploadkit.ErrThreatDetected) {
			t.Fatalf("expected threat, got: %v", err)
		}
		if store.putCount.Load() != 0 {
			t.Fatalf("Put must be zero, got %d", store.putCount.Load())
		}
	})
}

// TestUploadRequestApplicableRulesCleanMissSucceeds 验证存在适用规则且全部未命中时可成功上传。
func TestUploadRequestApplicableRulesCleanMissSucceeds(t *testing.T) {
	store := &countingStore{}
	content := testJPEG(t)
	uploader := newOfflineUploader(t, store, offline.RulePack{
		Version: "jpeg-clean-miss",
		Rules: []offline.Rule{
			{
				ID:     "jpeg.hash.miss",
				Kind:   "sha256",
				SHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				MIME:   []string{"image/jpeg"},
				Threat: "TEST.JPEG.Hash",
			},
			{
				ID:      "jpeg.bytes.miss",
				Kind:    "bytes",
				Pattern: hex.EncodeToString([]byte("NOT-IN-JPEG-BYTES")),
				MIME:    []string{"image/jpeg"},
				Threat:  "TEST.JPEG.Bytes",
			},
		},
	})
	result, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
		Source: uploadkit.FromBytes("photo.jpg", content),
	})
	if err != nil {
		t.Fatalf("clean miss should succeed: %v", err)
	}
	if store.putCount.Load() != 1 {
		t.Fatalf("expected one Put, got %d", store.putCount.Load())
	}
	if !bytes.Equal(store.objects[result.ObjectKey], content) {
		t.Fatal("stored content mismatch")
	}
}
