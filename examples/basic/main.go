package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/ClownSketch/uploadkit"
	"github.com/ClownSketch/uploadkit/store/local"
)

// main 演示从内存内容安全上传到本地存储。
func main() {
	root, err := os.MkdirTemp("", "uploadkit-example-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root)

	store, err := local.New(local.Config{Root: root})
	if err != nil {
		log.Fatal(err)
	}
	uploader, err := uploadkit.New(store)
	if err != nil {
		log.Fatal(err)
	}
	result, err := uploader.Upload(
		context.Background(),
		uploadkit.FromBytes("hello.txt", []byte("hello uploadkit")),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("object=%s size=%d sha256=%s\n", result.ObjectKey, result.Size, result.ChecksumSHA256)
}
