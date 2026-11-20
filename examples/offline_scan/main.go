package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ClownSketch/uploadkit"
	"github.com/ClownSketch/uploadkit/scanner/offline"
	"github.com/ClownSketch/uploadkit/store/local"
)

// main 演示生产装配：启动时加载本地规则包，普通上传自动执行必需扫描。
func main() {
	root, err := os.MkdirTemp("", "uploadkit-offline-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root)

	rulePath, digest, err := writeDemoRulePack(root)
	if err != nil {
		log.Fatal(err)
	}
	scanner, err := offline.NewFromFile(rulePath, digest)
	if err != nil {
		log.Fatal(err)
	}

	store, err := local.New(local.Config{Root: filepath.Join(root, "storage")})
	if err != nil {
		log.Fatal(err)
	}
	policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
		MaxFileSize:           1 << 20,
		AllowedMIMETypes:      []string{"text/plain"},
		RequireMalwareScanner: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 启动时一次性装配；规则无效或扫描器缺失会导致初始化失败。
	uploader, err := uploadkit.New(
		store,
		uploadkit.WithDefaultPolicy(policy),
		uploadkit.WithScanner(scanner),
	)
	if err != nil {
		log.Fatal(err)
	}

	result, err := uploader.Upload(
		context.Background(),
		uploadkit.FromBytes("ok.txt", []byte("business-safe-sample")),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("clean upload object=%s rules=%s\n", result.ObjectKey, scanner.Version())

	_, err = uploader.Upload(
		context.Background(),
		uploadkit.FromBytes("blocked.txt", []byte("DEMO-OFFLINE-THREAT-MARKER")),
	)
	if !errors.Is(err, uploadkit.ErrThreatDetected) {
		log.Fatalf("expected threat rejection, got: %v", err)
	}
	fmt.Printf("threat rejected as expected: %v\n", err)
}

// writeDemoRulePack 写入仅用于示例的无害测试规则，不能当作生产防护发布。
func writeDemoRulePack(root string) (path string, digest string, err error) {
	pack := offline.RulePack{
		Version:      "demo-test-only",
		MaxScanBytes: 1 << 20,
		Rules: []offline.Rule{{
			ID:      "demo.bytes.marker",
			Kind:    "bytes",
			Pattern: hex.EncodeToString([]byte("DEMO-OFFLINE-THREAT-MARKER")),
			MIME:    []string{"text/plain"},
			Threat:  "TEST.Demo.Marker",
		}},
	}
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return "", "", err
	}
	raw = append(raw, '\n')
	sum := sha256.Sum256(raw)
	path = filepath.Join(root, "rules.demo.json")
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(sum[:]), nil
}
