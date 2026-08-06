// Package clamav 通过 ClamAV INSTREAM 协议实现文件内容扫描器。
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ClownSketch/uploadkit"
)

const (
	defaultNetwork   = "tcp"            // defaultNetwork 默认连接类型
	defaultTimeout   = 30 * time.Second // defaultTimeout 默认扫描超时
	defaultChunkSize = 64 << 10         // defaultChunkSize 默认数据块大小
	maxChunkSize     = 1 << 20          // maxChunkSize 单个 INSTREAM 数据块上限
	maxResponseSize  = 8 << 10          // maxResponseSize ClamAV 响应长度上限
	streamCommand    = "zINSTREAM\x00"  // streamCommand ClamAV 流式扫描命令
)

// Config 定义 ClamAV 扫描器配置。
type Config struct {
	Network       string        // Network 网络类型，支持 tcp 或 unix
	Address       string        // Address ClamAV 地址
	Timeout       time.Duration // Timeout 单次扫描超时
	ChunkSize     int           // ChunkSize 流式发送块大小
	MaxStreamSize int64         // MaxStreamSize 可选的客户端流大小上限
}

// Scanner 使用 ClamAV clamd 扫描上传内容。
type Scanner struct {
	network       string        // network 连接类型
	address       string        // address clamd 地址
	timeout       time.Duration // timeout 单次扫描超时
	chunkSize     int           // chunkSize 流式数据块大小
	maxStreamSize int64         // maxStreamSize 客户端流大小上限
}

// New 创建 ClamAV 扫描器。
// @param config Config 扫描器配置
// @return result *Scanner 扫描器
// @return err error 配置错误
func New(config Config) (result *Scanner, err error) {
	// 规范网络类型，空值默认使用 TCP。
	network := strings.TrimSpace(config.Network)
	if network == "" {
		network = defaultNetwork
	}
	// INSTREAM 连接只支持 TCP 和 Unix Socket。
	if network != "tcp" && network != "unix" {
		return nil, fmt.Errorf("%w: unsupported ClamAV network", uploadkit.ErrInvalidConfig)
	}
	// 规范 clamd 服务地址。
	address := strings.TrimSpace(config.Address)
	// 空地址无法建立扫描连接。
	if address == "" {
		return nil, fmt.Errorf("%w: ClamAV address is empty", uploadkit.ErrInvalidConfig)
	}
	// 读取单次扫描超时配置。
	timeout := config.Timeout
	// 零值使用明确的默认超时。
	if timeout == 0 {
		timeout = defaultTimeout
	}
	// 负数超时无法用于连接和截止时间。
	if timeout < 0 {
		return nil, fmt.Errorf("%w: ClamAV timeout is invalid", uploadkit.ErrInvalidConfig)
	}
	// 读取 INSTREAM 数据块大小。
	chunkSize := config.ChunkSize
	// 零值使用 64KB 默认数据块。
	if chunkSize == 0 {
		chunkSize = defaultChunkSize
	}
	// 数据块和总流上限必须在协议安全范围内。
	if chunkSize < 1 || chunkSize > maxChunkSize || config.MaxStreamSize < 0 {
		return nil, fmt.Errorf("%w: ClamAV stream limit is invalid", uploadkit.ErrInvalidConfig)
	}
	// 保存完成校验的不可变扫描配置。
	return &Scanner{
		network:       network,
		address:       address,
		timeout:       timeout,
		chunkSize:     chunkSize,
		maxStreamSize: config.MaxStreamSize,
	}, nil
}

// Scan 将文件流发送给 ClamAV 并解析扫描结果。
// @param ctx context.Context 调用上下文
// @param file uploadkit.FileInfo 文件信息
// @param content io.Reader 文件内容
// @return result uploadkit.ScanResult 扫描结论
// @return err error 连接、协议或扫描错误
func (s *Scanner) Scan(ctx context.Context, file uploadkit.FileInfo, content io.Reader) (result uploadkit.ScanResult, err error) {
	// 扫描器或文件内容为空时无法执行协议交互。
	if s == nil || content == nil {
		return uploadkit.ScanResult{}, uploadkit.ErrInvalidConfig
	}
	// 扫描操作统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ScanResult{}, uploadkit.ErrNilContext
	}
	// 已知文件大小超过扫描器上限时不建立网络连接。
	if s.maxStreamSize > 0 && file.Size > s.maxStreamSize {
		return uploadkit.ScanResult{}, fmt.Errorf("ClamAV stream exceeds configured limit: actual=%d max=%d", file.Size, s.maxStreamSize)
	}
	// 创建带连接超时的标准网络拨号器。
	dialer := &net.Dialer{Timeout: s.timeout}
	// 按配置建立 TCP 或 Unix Socket 连接。
	connection, err := dialer.DialContext(ctx, s.network, s.address)
	// 建连失败时保留系统错误链。
	if err != nil {
		return uploadkit.ScanResult{}, fmt.Errorf("connect ClamAV: %w", err)
	}
	// 扫描完成后关闭 clamd 连接。
	defer connection.Close()
	// 上下文取消时立即缩短连接截止时间，打断正在阻塞的网络读写。
	stopCancellation := context.AfterFunc(ctx, func() {
		// 设置当前时间为截止时间，使进行中的网络操作立即返回。
		_ = connection.SetDeadline(time.Now())
	})
	// 扫描结束后停止取消回调，避免继续操作已经关闭的连接。
	defer stopCancellation()
	// 默认使用扫描器超时计算读写截止时间。
	deadline := time.Now().Add(s.timeout)
	// 调用方截止时间更早时优先服从上下文。
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	// 同时限制连接读写，避免 clamd 无响应时长期阻塞。
	if err = connection.SetDeadline(deadline); err != nil {
		// 截止时间设置期间收到取消时返回标准上下文错误。
		if contextErr := ctx.Err(); contextErr != nil {
			return uploadkit.ScanResult{}, contextErr
		}
		return uploadkit.ScanResult{}, fmt.Errorf("set ClamAV deadline: %w", err)
	}
	// 发送以零字节结束的 INSTREAM 命令。
	if err = writeAll(connection, []byte(streamCommand)); err != nil {
		// 取消回调会通过连接截止时间中断写入，此时保留上下文语义。
		if contextErr := ctx.Err(); contextErr != nil {
			return uploadkit.ScanResult{}, contextErr
		}
		return uploadkit.ScanResult{}, fmt.Errorf("send ClamAV command: %w", err)
	}
	// 按协议分块发送完整文件内容。
	if err = s.writeStream(ctx, connection, content); err != nil {
		// 网络写入被取消回调打断时返回标准上下文错误。
		if contextErr := ctx.Err(); contextErr != nil {
			return uploadkit.ScanResult{}, contextErr
		}
		return uploadkit.ScanResult{}, err
	}
	// 限制 clamd 响应大小，防止异常服务端持续占用内存。
	limitedResponse := &io.LimitedReader{R: connection, N: maxResponseSize + 1}
	// 读取以零字节结束的完整响应。
	response, err := bufio.NewReader(limitedResponse).ReadString(0)
	// 连接 EOF 可以表示服务端已发送无终止符响应，其他错误直接返回。
	if err != nil && !errors.Is(err, io.EOF) {
		// 取消回调会通过连接截止时间打断读取，此时保留上下文语义。
		if contextErr := ctx.Err(); contextErr != nil {
			return uploadkit.ScanResult{}, contextErr
		}
		return uploadkit.ScanResult{}, fmt.Errorf("read ClamAV response: %w", err)
	}
	// 实际响应超过协议上限时拒绝解析。
	if len(response) > maxResponseSize {
		return uploadkit.ScanResult{}, errors.New("ClamAV response exceeds size limit")
	}
	// 将协议文本转换为统一扫描结果。
	return parseResponse(response)
}

// writeStream 按 INSTREAM 协议发送文件内容。
// @param ctx context.Context 调用上下文
// @param destination io.Writer clamd 连接
// @param source io.Reader 文件内容
// @return err error 上下文或网络错误
func (s *Scanner) writeStream(ctx context.Context, destination io.Writer, source io.Reader) error {
	// 按扫描器配置分配单个发送缓冲区。
	buffer := make([]byte, s.chunkSize)
	// totalBytes 记录实际发送总量，用于校验未知大小来源。
	var totalBytes int64
	// 持续发送直到来源读取完成或出现错误。
	for {
		// 每个数据块读取前响应上下文取消。
		if err := ctx.Err(); err != nil {
			return err
		}
		// 从文件内容读取下一个数据块。
		readCount, readErr := source.Read(buffer)
		// 当前数据块非空时写入 INSTREAM 帧。
		if readCount > 0 {
			// 累加真实发送字节数。
			totalBytes += int64(readCount)
			// 未知大小来源超过扫描上限时立即终止发送。
			if s.maxStreamSize > 0 && totalBytes > s.maxStreamSize {
				return fmt.Errorf("ClamAV stream exceeds configured limit: actual=%d max=%d", totalBytes, s.maxStreamSize)
			}
			// INSTREAM 使用四字节大端长度头。
			var sizeHeader [4]byte
			// 当前数据块不会超过 uint32 协议范围。
			binary.BigEndian.PutUint32(sizeHeader[:], uint32(readCount))
			// 先完整发送数据块长度。
			if err := writeAll(destination, sizeHeader[:]); err != nil {
				return fmt.Errorf("send ClamAV chunk size: %w", err)
			}
			// 再完整发送当前数据块内容。
			if err := writeAll(destination, buffer[:readCount]); err != nil {
				return fmt.Errorf("send ClamAV chunk: %w", err)
			}
		}
		// 当前读取返回状态时处理完成或失败分支。
		if readErr != nil {
			// EOF 后发送四字节零长度帧结束 INSTREAM。
			if errors.Is(readErr, io.EOF) {
				// 全零数组表示协议结束帧。
				var end [4]byte
				// 结束帧也必须完整写入连接。
				if err := writeAll(destination, end[:]); err != nil {
					return fmt.Errorf("finish ClamAV stream: %w", err)
				}
				// 文件内容已经完整发送。
				return nil
			}
			// 其他读取错误保留底层原因。
			return fmt.Errorf("read ClamAV stream: %w", readErr)
		}
	}
}

// writeAll 完整写入协议数据并拒绝短写。
// @param destination io.Writer 写入目标
// @param data []byte 待写数据
// @return err error 写入错误
func writeAll(destination io.Writer, data []byte) error {
	// 持续写入直到当前协议片段全部完成。
	for len(data) > 0 {
		// 写入剩余未发送的数据。
		written, err := destination.Write(data)
		// 网络写入失败时立即返回。
		if err != nil {
			return err
		}
		// 无进展或非法写入数量按短写处理。
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		// 移除已经成功发送的数据范围。
		data = data[written:]
	}
	// 当前协议片段已经完整写入。
	return nil
}

// parseResponse 解析 ClamAV INSTREAM 响应。
// @param response string 原始响应
// @return result uploadkit.ScanResult 扫描结果
// @return err error 协议或服务错误
func parseResponse(response string) (result uploadkit.ScanResult, err error) {
	// 清除协议零终止符和文本两端空白。
	response = strings.TrimSpace(strings.TrimRight(response, "\x00"))
	// : OK 表示 clamd 未发现威胁。
	if strings.HasSuffix(response, ": OK") {
		return uploadkit.ScanResult{Clean: true}, nil
	}
	// FOUND 表示 clamd 返回了威胁名称。
	if strings.HasSuffix(response, " FOUND") {
		// 先移除 FOUND 状态文本。
		message := strings.TrimSpace(strings.TrimSuffix(response, " FOUND"))
		// 响应中冒号前为流名称，只保留威胁描述。
		if separator := strings.Index(message, ":"); separator >= 0 {
			message = strings.TrimSpace(message[separator+1:])
		}
		// 返回明确的不安全扫描结果。
		return uploadkit.ScanResult{Clean: false, Threat: message}, nil
	}
	// 空响应无法确定文件是否安全。
	if response == "" {
		return uploadkit.ScanResult{}, errors.New("ClamAV returned an empty response")
	}
	// 其他响应按 clamd 服务错误处理。
	return uploadkit.ScanResult{}, fmt.Errorf("ClamAV scan failed: %s", response)
}
