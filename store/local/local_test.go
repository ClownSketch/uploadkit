package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ClownSketch/uploadkit"
)

// TestStoreUploadDelete 验证本地存储完整上传和删除流程。
func TestStoreUploadDelete(t *testing.T) {
	root := t.TempDir()
	store, err := New(Config{Root: root})
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	if err = store.Ping(context.Background()); err != nil {
		t.Fatalf("check local store: %v", err)
	}
	policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
		MaxFileSize:      1024,
		AllowedMIMETypes: []string{"text/plain"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	uploader, err := uploadkit.New(store, uploadkit.WithKeyGenerator(func(input uploadkit.KeyInput) (string, error) {
		return "tenant/report.txt", nil
	}))
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	result, err := uploader.UploadRequest(context.Background(), uploadkit.Request{
		Source: uploadkit.FromBytes("report.txt", []byte("hello uploadkit")),
		Policy: policy,
	})
	if err != nil {
		t.Fatalf("upload local object: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "tenant", "report.txt"))
	if err != nil {
		t.Fatalf("read local object: %v", err)
	}
	if string(content) != "hello uploadkit" {
		t.Fatalf("unexpected local content: %s", content)
	}
	if result.ObjectKey != "tenant/report.txt" {
		t.Fatalf("unexpected local object key: %s", result.ObjectKey)
	}
	_, err = uploader.UploadRequest(context.Background(), uploadkit.Request{
		Source: uploadkit.FromBytes("report.txt", []byte("replacement")),
		Policy: policy,
	})
	if !errors.Is(err, uploadkit.ErrObjectExists) {
		t.Fatalf("expected duplicate rejection, got: %v", err)
	}
	if err = store.Delete(context.Background(), result.ObjectKey); err != nil {
		t.Fatalf("delete local object: %v", err)
	}
	if err = store.Delete(context.Background(), result.ObjectKey); err != nil {
		t.Fatalf("delete missing local object: %v", err)
	}
}

// TestStoreRejectsSymlinkEscape 验证符号链接不能越过存储根目录。
func TestStoreRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic link permissions differ on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("create symbolic link: %v", err)
	}
	store, err := New(Config{Root: root})
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	body := strings.NewReader("blocked")
	_, err = store.Put(context.Background(), uploadkit.PutObject{
		Key:                "escape/file.txt",
		Body:               body,
		Size:               int64(body.Len()),
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
	})
	if !errors.Is(err, uploadkit.ErrInvalidObjectKey) {
		t.Fatalf("expected symlink escape rejection, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "file.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("escaped file was created: %v", statErr)
	}
}

// TestStoreDeleteRejectsSymlinkEscape 验证删除对象不会穿过中间符号链。
func TestStoreDeleteRejectsSymlinkEscape(t *testing.T) {
	// Windows 创建符号链需要额外权限，不在该环境执行。
	if runtime.GOOS == "windows" {
		t.Skip("symbolic link permissions differ on Windows")
	}
	// 创建独立的存储根目录和外部目录。
	root := t.TempDir()
	outside := t.TempDir()
	// 在外部目录中写入不允许删除的文件。
	outsideFile := filepath.Join(outside, "file.txt")
	if err := os.WriteFile(outsideFile, []byte("protected"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	// 在存储根目录中创建指向外部目录的符号链。
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("create symbolic link: %v", err)
	}
	// 创建本地存储适配器。
	store, err := New(Config{Root: root})
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	// 删除通过符号链指向外部的对象必须被拒绝。
	if err = store.Delete(context.Background(), "escape/file.txt"); !errors.Is(err, uploadkit.ErrInvalidObjectKey) {
		t.Fatalf("expected symlink escape rejection, got: %v", err)
	}
	// 外部文件必须保持原样。
	content, err := os.ReadFile(outsideFile)
	if err != nil || string(content) != "protected" {
		t.Fatalf("outside file changed: content=%q err=%v", content, err)
	}
}

// TestStoreRejectsSizeMismatch 验证本地适配器不会提交不完整对象。
func TestStoreRejectsSizeMismatch(t *testing.T) {
	root := t.TempDir()
	store, err := New(Config{Root: root})
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	body := strings.NewReader("short")
	_, err = store.Put(context.Background(), uploadkit.PutObject{
		Key:                "size/file.txt",
		Body:               body,
		Size:               100,
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ChecksumSHA256:     strings.Repeat("a", 64),
	})
	if err == nil {
		t.Fatal("expected size mismatch error")
	}
	if _, statErr := os.Stat(filepath.Join(root, "size", "file.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial object was committed: %v", statErr)
	}
}

// TestValidateWindowsObjectKey 验证 Windows 特殊路径语义不会进入本地存储。
func TestValidateWindowsObjectKey(t *testing.T) {
	// invalidKeys 覆盖保留字符、数据流、尾随字符和系统设备名称。
	invalidKeys := []string{
		"docs/file.txt:stream",
		"docs/file?.txt",
		"docs/trailing.",
		"docs/trailing ",
		"docs/CON",
		"docs/con.txt",
		"docs/NUL.json",
		"docs/COM1.log",
		"docs/LPT9",
	}
	// 每一个特殊路径都必须返回统一对象键错误。
	for _, objectKey := range invalidKeys {
		if err := validateWindowsObjectKey(objectKey); !errors.Is(err, uploadkit.ErrInvalidObjectKey) {
			t.Fatalf("expected invalid Windows object key %q, got: %v", objectKey, err)
		}
	}
	// 普通名称和设备名称前缀不能被误判。
	validKeys := []string{"docs/content.txt", "docs/connection.txt", "docs/COM10.log", "docs/LPT0"}
	// 每一个普通路径都必须通过 Windows 规则校验。
	for _, objectKey := range validKeys {
		if err := validateWindowsObjectKey(objectKey); err != nil {
			t.Fatalf("validate Windows object key %q: %v", objectKey, err)
		}
	}
}
