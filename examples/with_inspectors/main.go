package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ClownSketch/uploadkit"
	"github.com/ClownSketch/uploadkit/store/local"
)

// main 演示普通上传保持现有签名，以及单次请求追加 Inspector。
func main() {
	root, err := os.MkdirTemp("", "uploadkit-inspectors-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root)

	store, err := local.New(local.Config{Root: root})
	if err != nil {
		log.Fatal(err)
	}

	// 实例级检查器对所有上传生效，调用方不能跳过。
	uploader, err := uploadkit.New(store, uploadkit.WithInspector(uploadkit.InspectorFunc(func(
		ctx context.Context,
		file uploadkit.FileInfo,
		content io.Reader,
	) error {
		body, readErr := io.ReadAll(content)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), "FORBIDDEN") {
			return fmt.Errorf("content rejected by instance inspector")
		}
		return ctx.Err()
	})))
	if err != nil {
		log.Fatal(err)
	}

	// 普通上传：保持现有签名，服务层不显式调用扫描。
	result, err := uploader.Upload(
		context.Background(),
		uploadkit.FromBytes("notice.txt", []byte("hello uploadkit")),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plain upload object=%s\n", result.ObjectKey)

	// 特殊用途：只为本次请求追加内容检查，不替换实例检查器。
	receiptInspector := uploadkit.InspectorFunc(func(
		ctx context.Context,
		file uploadkit.FileInfo,
		content io.Reader,
	) error {
		body, readErr := io.ReadAll(content)
		if readErr != nil {
			return readErr
		}
		if !strings.Contains(string(body), "RECEIPT") {
			return fmt.Errorf("receipt marker missing")
		}
		return ctx.Err()
	})
	req := uploadkit.Request{
		Source: uploadkit.FromBytes("receipt.txt", []byte("RECEIPT-OK")),
	}
	result, err = uploader.UploadRequest(context.Background(), req.WithInspectors(receiptInspector))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("inspected upload object=%s\n", result.ObjectKey)
}
