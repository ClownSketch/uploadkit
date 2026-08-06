package uploadkit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSourceAdapters 验证各种常用输入都能统一读取。
func TestSourceAdapters(t *testing.T) {
	content := []byte("source content")
	tempPath := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(tempPath, content, 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	file, err := os.Open(tempPath)
	if err != nil {
		t.Fatalf("open source file: %v", err)
	}
	defer file.Close()
	readSeekerSource, err := FromReadSeeker("source.txt", int64(len(content)), bytes.NewReader(content))
	if err != nil {
		t.Fatalf("create read seeker source: %v", err)
	}
	pathSource, err := FromPath(tempPath)
	if err != nil {
		t.Fatalf("create path source: %v", err)
	}
	fileSource, err := FromFile(file)
	if err != nil {
		t.Fatalf("create file source: %v", err)
	}
	fsSource, err := FromFS(os.DirFS(filepath.Dir(tempPath)), filepath.Base(tempPath))
	if err != nil {
		t.Fatalf("create fs source: %v", err)
	}
	multipartSource := testMultipartSource(t, content)
	sources := []Source{
		FromBytes("source.txt", content),
		readSeekerSource,
		pathSource,
		fileSource,
		fsSource,
		multipartSource,
	}
	for index, source := range sources {
		reader, openErr := source.Open(context.Background())
		if openErr != nil {
			t.Fatalf("open source %d: %v", index, openErr)
		}
		actual, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read source %d: %v", index, errors.Join(readErr, closeErr))
		}
		if !bytes.Equal(actual, content) {
			t.Fatalf("source %d changed content: %q", index, actual)
		}
	}
}

// TestReaderSourceCanOnlyBeConsumedOnce 验证一次性 Reader 不会被静默重复使用。
func TestReaderSourceCanOnlyBeConsumedOnce(t *testing.T) {
	source, err := FromReader("source.txt", -1, strings.NewReader("content"))
	if err != nil {
		t.Fatalf("create reader source: %v", err)
	}
	reader, err := source.Open(context.Background())
	if err != nil {
		t.Fatalf("open reader source: %v", err)
	}
	_ = reader.Close()
	if _, err = source.Open(context.Background()); !errors.Is(err, ErrSourceConsumed) {
		t.Fatalf("expected consumed error, got: %v", err)
	}
}

// TestReadSeekerSourceSerializesReaders 验证共享 ReadSeeker 的读取生命周期不会并发交叉。
func TestReadSeekerSourceSerializesReaders(t *testing.T) {
	// 创建可以重复打开的共享 Reader 来源。
	source, err := FromReadSeeker("source.txt", 7, strings.NewReader("content"))
	if err != nil {
		t.Fatalf("create read seeker source: %v", err)
	}
	// 第一次打开持有共享 Reader 的读取权。
	first, err := source.Open(context.Background())
	if err != nil {
		t.Fatalf("open first reader: %v", err)
	}
	// opened 接收第二次打开结果。
	opened := make(chan io.ReadCloser, 1)
	// openErrors 接收第二次打开错误。
	openErrors := make(chan error, 1)
	// 并发尝试再次打开同一个来源。
	go func() {
		reader, openErr := source.Open(context.Background())
		if openErr != nil {
			openErrors <- openErr
			return
		}
		opened <- reader
	}()
	// 第一个 Reader 未关闭前，第二次打开不能共享可变游标。
	select {
	case <-opened:
		t.Fatal("second reader opened before first reader closed")
	case openErr := <-openErrors:
		t.Fatalf("open second reader: %v", openErr)
	case <-time.After(20 * time.Millisecond):
	}
	// 关闭第一次读取并释放共享 Reader。
	if err = first.Close(); err != nil {
		t.Fatalf("close first reader: %v", err)
	}
	// 第二次打开现在必须完成并从内容起点读取。
	select {
	case second := <-opened:
		content, readErr := io.ReadAll(second)
		closeErr := second.Close()
		if readErr != nil || closeErr != nil || string(content) != "content" {
			t.Fatalf("read second reader: %q %v", content, errors.Join(readErr, closeErr))
		}
	case openErr := <-openErrors:
		t.Fatalf("open second reader: %v", openErr)
	case <-time.After(time.Second):
		t.Fatal("second reader did not open after first reader closed")
	}
}

// TestReadSeekerSourceWaitHonorsContext 验证等待共享 Reader 时可以及时取消。
func TestReadSeekerSourceWaitHonorsContext(t *testing.T) {
	// 创建可以重复打开的共享 Reader 来源。
	source, err := FromReadSeeker("source.txt", 7, strings.NewReader("content"))
	if err != nil {
		t.Fatalf("create read seeker source: %v", err)
	}
	// 第一次打开占用共享 Reader。
	first, err := source.Open(context.Background())
	if err != nil {
		t.Fatalf("open first reader: %v", err)
	}
	// 测试结束前释放第一次读取。
	defer first.Close()
	// 创建已经取消的第二次打开上下文。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// 等待锁期间必须立即返回标准取消错误。
	if _, err = source.Open(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got: %v", err)
	}
}

// testMultipartSource 创建标准 multipart 文件来源。
// @param t *testing.T 测试上下文
// @param content []byte 文件内容
// @return result Source multipart 来源
func testMultipartSource(t *testing.T, content []byte) Source {
	t.Helper()
	body := bytes.NewBuffer(nil)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "source.txt")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err = part.Write(content); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	request := httptest.NewRequest("POST", "/upload", body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	if err = request.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("parse multipart body: %v", err)
	}
	fileHeader := request.MultipartForm.File["file"][0]
	source, err := FromMultipart(fileHeader)
	if err != nil {
		t.Fatalf("create multipart source: %v", err)
	}
	return source
}
