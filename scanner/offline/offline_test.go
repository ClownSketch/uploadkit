package offline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
)

const (
	eicarTestString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	crossChunkMark  = "UPLOADKIT-OFFLINE-CROSS-CHUNK-MARKER-v1"
)

// testRuleDigest 返回测试规则包文件摘要。
func testRuleDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rules.test.sha256"))
	if err != nil {
		t.Fatalf("read rule digest: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// TestNewFromFileRejectsBrokenPacks 验证损坏或空规则包不能启动为健康引擎。
func TestNewFromFileRejectsBrokenPacks(t *testing.T) {
	digest := testRuleDigest(t)
	if _, err := NewFromFile(filepath.Join("testdata", "rules.test.json"), digest); err != nil {
		t.Fatalf("load valid rule pack: %v", err)
	}
	if _, err := NewFromFile(filepath.Join("testdata", "rules.test.json"), "00"+digest[2:]); !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected digest mismatch, got: %v", err)
	}
	emptyRaw, err := os.ReadFile(filepath.Join("testdata", "rules.empty.json"))
	if err != nil {
		t.Fatalf("read empty pack: %v", err)
	}
	emptyDigest := sha256.Sum256(emptyRaw)
	if _, err = NewFromFile(filepath.Join("testdata", "rules.empty.json"), hex.EncodeToString(emptyDigest[:])); !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected empty pack rejection, got: %v", err)
	}
	corruptRaw, err := os.ReadFile(filepath.Join("testdata", "rules.corrupt.json"))
	if err != nil {
		t.Fatalf("read corrupt pack: %v", err)
	}
	corruptDigest := sha256.Sum256(corruptRaw)
	if _, err = NewFromFile(filepath.Join("testdata", "rules.corrupt.json"), hex.EncodeToString(corruptDigest[:])); !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected corrupt pack rejection, got: %v", err)
	}
}

// TestScanHashAndBytes 验证摘要命中与字节特征命中。
func TestScanHashAndBytes(t *testing.T) {
	scanner, err := NewFromFile(filepath.Join("testdata", "rules.test.json"), testRuleDigest(t))
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	eicar := []byte(eicarTestString)
	sum := sha256.Sum256(eicar)
	result, err := scanner.Scan(context.Background(), uploadkit.FileInfo{
		OriginalName:   "eicar.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(eicar)),
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	}, bytes.NewReader(eicar))
	if err != nil || result.Clean || result.Threat != "TEST.EICAR.Hash" {
		t.Fatalf("expected hash hit, got %+v %v", result, err)
	}
	clean := []byte("hello offline scanner")
	cleanSum := sha256.Sum256(clean)
	result, err = scanner.Scan(context.Background(), uploadkit.FileInfo{
		OriginalName:   "clean.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(clean)),
		ChecksumSHA256: hex.EncodeToString(cleanSum[:]),
	}, bytes.NewReader(clean))
	if err != nil || !result.Clean || result.Threat != "" {
		t.Fatalf("expected clean result, got %+v %v", result, err)
	}
}

// TestScanCrossChunkPattern 验证特征跨越读取块边界时不会漏检。
func TestScanCrossChunkPattern(t *testing.T) {
	scanner, err := NewFromFile(filepath.Join("testdata", "rules.test.json"), testRuleDigest(t))
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	prefix := bytes.Repeat([]byte("a"), scanChunkSize-8)
	content := append(prefix, []byte(crossChunkMark)...)
	sum := sha256.Sum256(content)
	result, err := scanner.Scan(context.Background(), uploadkit.FileInfo{
		OriginalName:   "cross.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(content)),
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	}, bytes.NewReader(content))
	if err != nil || result.Clean || result.Threat != "TEST.CrossChunk.Marker" {
		t.Fatalf("expected cross-chunk hit, got %+v %v", result, err)
	}
}

// TestScanNoApplicableRulesIsIncomplete 验证没有任何适用规则时返回未完成而不是清洁。
func TestScanNoApplicableRulesIsIncomplete(t *testing.T) {
	pack := RulePack{
		Version: "pdf-only",
		Rules: []Rule{{
			ID:     "pdf.hash",
			Kind:   "sha256",
			SHA256: strings.Repeat("e", 64),
			MIME:   []string{"application/pdf"},
			Threat: "TEST.PDF",
		}},
	}
	raw, err := jsonMarshalPack(pack)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	digest := sha256.Sum256(raw)
	loaded, _, err := LoadRulePackBytes(raw, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	scanner, err := New(Config{RulePack: loaded, RulePackDigest: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	content := []byte("plain text without pdf rules")
	sum := sha256.Sum256(content)
	_, err = scanner.Scan(context.Background(), uploadkit.FileInfo{
		OriginalName:   "note.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(content)),
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	}, bytes.NewReader(content))
	if !errors.Is(err, uploadkit.ErrScanIncomplete) {
		t.Fatalf("expected incomplete scan, got: %v", err)
	}
}

// TestScanIncompleteWhenOverCapacity 验证超出检测能力时返回未完成而不是未命中。
func TestScanIncompleteWhenOverCapacity(t *testing.T) {
	pack := RulePack{
		Version:      "capacity-test",
		MaxScanBytes: 16,
		Rules: []Rule{{
			ID:      "test.bytes.tiny",
			Kind:    "bytes",
			Pattern: hex.EncodeToString([]byte("MARK")),
			Threat:  "TEST.Tiny",
		}},
	}
	raw, err := jsonMarshalPack(pack)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	digest := sha256.Sum256(raw)
	loaded, _, err := LoadRulePackBytes(raw, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	scanner, err := New(Config{RulePack: loaded, RulePackDigest: hex.EncodeToString(digest[:]), MaxScanBytes: 16})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	content := bytes.Repeat([]byte("b"), 32)
	sum := sha256.Sum256(content)
	_, err = scanner.Scan(context.Background(), uploadkit.FileInfo{
		OriginalName:   "large.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(content)),
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	}, bytes.NewReader(content))
	if !errors.Is(err, uploadkit.ErrScanIncomplete) {
		t.Fatalf("expected incomplete scan, got: %v", err)
	}
}

// TestScanHonorsContextCancel 验证扫描期间响应上下文取消。
func TestScanHonorsContextCancel(t *testing.T) {
	scanner, err := NewFromFile(filepath.Join("testdata", "rules.test.json"), testRuleDigest(t))
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	content := bytes.Repeat([]byte("c"), scanChunkSize*2)
	sum := sha256.Sum256(content)
	_, err = scanner.Scan(ctx, uploadkit.FileInfo{
		OriginalName:   "cancel.txt",
		MIMEType:       "text/plain",
		Size:           int64(len(content)),
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	}, &slowReader{Reader: bytes.NewReader(content), delay: 5 * time.Millisecond})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled scan, got: %v", err)
	}
}

// jsonMarshalPack 以稳定 JSON 编码规则包。
func jsonMarshalPack(pack RulePack) ([]byte, error) {
	return json.Marshal(pack)
}

// slowReader 在每次读取前等待，便于取消测试。
type slowReader struct {
	*bytes.Reader
	delay time.Duration
}

// Read 延迟后读取下一分块。
func (r *slowReader) Read(p []byte) (int, error) {
	time.Sleep(r.delay)
	return r.Reader.Read(p)
}
