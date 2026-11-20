package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClownSketch/uploadkit"
)

// sizedRulePackRaw 生成指定原始字节长度的合法规则包，测试内临时构造，不落库存档。
func sizedRulePackRaw(t *testing.T, size int) []byte {
	t.Helper()
	prefix := []byte(`{"version":"size-boundary","rules":[{"id":"test.hash.size","kind":"sha256","sha256":"` + strings.Repeat("a", 64) + `","mime":["text/plain"],"threat":"TEST.Size"}],"padding":"`)
	suffix := []byte(`"}`)
	pad := size - len(prefix) - len(suffix)
	if pad < 0 {
		t.Fatalf("target size too small: %d", size)
	}
	raw := append(append(prefix, []byte(strings.Repeat("z", pad))...), suffix...)
	if len(raw) != size {
		t.Fatalf("failed to build pack of size %d, got %d", size, len(raw))
	}
	var decoded RulePack
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("sized pack must remain valid JSON: %v", err)
	}
	if decoded.Version != "size-boundary" || len(decoded.Rules) != 1 {
		t.Fatalf("unexpected decoded pack: %+v", decoded)
	}
	return raw
}

// TestLoadRulePackBytesSizeBoundary 验证字节入口恰好上限可加载、超过一字节拒绝。
func TestLoadRulePackBytesSizeBoundary(t *testing.T) {
	exact := sizedRulePackRaw(t, MaxRulePackBytes)
	sum := sha256.Sum256(exact)
	digest := hex.EncodeToString(sum[:])
	if _, got, err := LoadRulePackBytes(exact, digest); err != nil || got != digest {
		t.Fatalf("exact max size must load: digest=%s err=%v", got, err)
	}

	over := sizedRulePackRaw(t, MaxRulePackBytes+1)
	overSum := sha256.Sum256(over)
	overDigest := hex.EncodeToString(overSum[:])
	_, _, err := LoadRulePackBytes(over, overDigest)
	if !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected oversized bytes rejection, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected max size error detail, got: %v", err)
	}
}

// TestLoadRulePackFileSizeBoundary 验证文件入口恰好上限可加载、超过一字节拒绝。
func TestLoadRulePackFileSizeBoundary(t *testing.T) {
	exact := sizedRulePackRaw(t, MaxRulePackBytes)
	sum := sha256.Sum256(exact)
	digest := hex.EncodeToString(sum[:])
	exactPath := filepath.Join(t.TempDir(), "exact.json")
	if err := os.WriteFile(exactPath, exact, 0o600); err != nil {
		t.Fatalf("write exact pack: %v", err)
	}
	if _, got, err := LoadRulePackFile(exactPath, digest); err != nil || got != digest {
		t.Fatalf("exact max size file must load: digest=%s err=%v", got, err)
	}

	over := sizedRulePackRaw(t, MaxRulePackBytes+1)
	overSum := sha256.Sum256(over)
	overDigest := hex.EncodeToString(overSum[:])
	overPath := filepath.Join(t.TempDir(), "over.json")
	if err := os.WriteFile(overPath, over, 0o600); err != nil {
		t.Fatalf("write oversized pack: %v", err)
	}
	if _, _, err := LoadRulePackFile(overPath, overDigest); !errors.Is(err, uploadkit.ErrInvalidConfig) {
		t.Fatalf("expected oversized file rejection, got: %v", err)
	}
}
