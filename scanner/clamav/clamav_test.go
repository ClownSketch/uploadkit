package clamav

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ClownSketch/uploadkit"
)

// TestScannerScan 验证 ClamAV INSTREAM 协议和结果解析。
func TestScannerScan(t *testing.T) {
	tests := []struct {
		name     string
		response string
		clean    bool
		threat   string
	}{
		{name: "clean", response: "stream: OK\x00", clean: true},
		{name: "threat", response: "stream: Eicar-Signature FOUND\x00", threat: "Eicar-Signature"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, received, closeServer := startClamAVServer(t, test.response)
			defer closeServer()
			scanner, err := New(Config{Address: address, Timeout: time.Second, ChunkSize: 3})
			if err != nil {
				t.Fatalf("create scanner: %v", err)
			}
			content := "upload content"
			result, err := scanner.Scan(context.Background(), uploadkit.FileInfo{Size: int64(len(content))}, strings.NewReader(content))
			if err != nil {
				t.Fatalf("scan content: %v", err)
			}
			if result.Clean != test.clean || result.Threat != test.threat {
				t.Fatalf("unexpected scan result: %+v", result)
			}
			if actual := <-received; actual != content {
				t.Fatalf("unexpected streamed content: %s", actual)
			}
		})
	}
}

// TestScannerStreamLimit 验证客户端流大小上限。
func TestScannerStreamLimit(t *testing.T) {
	scanner, err := New(Config{Address: "127.0.0.1:3310", MaxStreamSize: 4})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	_, err = scanner.Scan(context.Background(), uploadkit.FileInfo{Size: 5}, strings.NewReader("12345"))
	if err == nil {
		t.Fatal("expected stream limit error")
	}
}

// TestScannerResponseLimit 验证异常 ClamAV 响应不会无限占用内存。
func TestScannerResponseLimit(t *testing.T) {
	address, _, closeServer := startClamAVServer(t, strings.Repeat("x", maxResponseSize+1))
	defer closeServer()
	scanner, err := New(Config{Address: address, Timeout: time.Second})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	_, err = scanner.Scan(context.Background(), uploadkit.FileInfo{Size: 4}, strings.NewReader("test"))
	if err == nil {
		t.Fatal("expected oversized response error")
	}
}

// TestScannerCancellation 验证调用方取消可以立即打断阻塞中的响应读取。
func TestScannerCancellation(t *testing.T) {
	// 创建只接收扫描内容但不返回结果的测试服务端。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake ClamAV: %v", err)
	}
	// 测试结束后关闭监听器并释放端口。
	defer listener.Close()
	// received 在服务端完整收到 INSTREAM 内容后发出信号。
	received := make(chan struct{})
	// releaseServer 用于结束测试服务端连接。
	releaseServer := make(chan struct{})
	// 启动一个故意阻塞响应阶段的测试服务端。
	go func() {
		// 接收扫描器建立的连接。
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		// 服务端退出时关闭连接。
		defer connection.Close()
		// 读取并校验 INSTREAM 命令。
		command := make([]byte, len(streamCommand))
		if _, readErr := io.ReadFull(connection, command); readErr != nil || string(command) != streamCommand {
			return
		}
		// 持续读取完整的 INSTREAM 数据帧。
		for {
			// 读取当前数据帧长度。
			var sizeHeader [4]byte
			if _, readErr := io.ReadFull(connection, sizeHeader[:]); readErr != nil {
				return
			}
			// 零长度帧表示文件内容发送完成。
			chunkSize := binary.BigEndian.Uint32(sizeHeader[:])
			if chunkSize == 0 {
				break
			}
			// 丢弃当前数据帧内容。
			if _, readErr := io.CopyN(io.Discard, connection, int64(chunkSize)); readErr != nil {
				return
			}
		}
		// 通知测试线程扫描器已经进入响应等待阶段。
		close(received)
		// 保持连接不返回响应，直到测试主动结束。
		<-releaseServer
	}()
	// 创建一个网络超时明显长于取消等待的扫描器。
	scanner, err := New(Config{Address: listener.Addr().String(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	// 创建可主动取消的扫描上下文。
	ctx, cancel := context.WithCancel(context.Background())
	// scanResult 接收异步扫描结果。
	scanResult := make(chan error, 1)
	// 启动扫描并等待服务端进入阻塞响应阶段。
	go func() {
		_, scanErr := scanner.Scan(ctx, uploadkit.FileInfo{Size: 4}, strings.NewReader("test"))
		scanResult <- scanErr
	}()
	// 确认服务端已经完整接收内容。
	<-received
	// 记录取消时间用于验证响应速度。
	canceledAt := time.Now()
	// 取消调用方上下文。
	cancel()
	// 等待扫描器返回取消结果。
	scanErr := <-scanResult
	// 允许测试服务端结束阻塞。
	close(releaseServer)
	// 扫描结果必须保留标准取消错误。
	if !errors.Is(scanErr, context.Canceled) {
		t.Fatalf("expected context cancellation, got: %v", scanErr)
	}
	// 取消不能继续等待扫描器的固定网络超时。
	if elapsed := time.Since(canceledAt); elapsed > 500*time.Millisecond {
		t.Fatalf("cancellation returned too slowly: %s", elapsed)
	}
}

// startClamAVServer 创建最小 INSTREAM 测试服务端。
// @param t *testing.T 测试上下文
// @param response string 扫描响应
// @return address string 服务地址
// @return received <-chan string 接收内容
// @return closeServer func() 关闭方法
func startClamAVServer(t *testing.T, response string) (address string, received <-chan string, closeServer func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake ClamAV: %v", err)
	}
	contentChannel := make(chan string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		command := make([]byte, len(streamCommand))
		if _, readErr := io.ReadFull(connection, command); readErr != nil || string(command) != streamCommand {
			return
		}
		var content strings.Builder
		for {
			var sizeHeader [4]byte
			if _, readErr := io.ReadFull(connection, sizeHeader[:]); readErr != nil {
				return
			}
			chunkSize := binary.BigEndian.Uint32(sizeHeader[:])
			if chunkSize == 0 {
				break
			}
			chunk := make([]byte, chunkSize)
			if _, readErr := io.ReadFull(connection, chunk); readErr != nil {
				return
			}
			content.Write(chunk)
		}
		contentChannel <- content.String()
		_, _ = io.WriteString(connection, response)
	}()
	return listener.Addr().String(), contentChannel, func() {
		_ = listener.Close()
	}
}
