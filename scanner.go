package uploadkit

import (
	"context"
	"fmt"
	"io"
)

// FileInfo 描述扫描器和检查器可使用的可信文件信息。
type FileInfo struct {
	OriginalName   string // OriginalName 清理后的原始名称
	MIMEType       string // MIMEType 真实文件类型
	Size           int64  // Size 实际文件大小
	ChecksumSHA256 string // ChecksumSHA256 十六进制 SHA-256
}

// ScanResult 描述一次病毒扫描结论。
type ScanResult struct {
	Clean  bool   // Clean 是否确认没有发现威胁
	Threat string // Threat 扫描器返回的威胁名称
}

// Scanner 定义病毒和恶意内容扫描扩展。
type Scanner interface {
	// Scan 检查一个从起点开始的文件流。
	Scan(ctx context.Context, file FileInfo, content io.Reader) (ScanResult, error)
}

// ScannerFunc 将普通方法适配为 Scanner。
type ScannerFunc func(ctx context.Context, file FileInfo, content io.Reader) (ScanResult, error)

// Scan 执行适配后的扫描方法。
// @param ctx context.Context 调用上下文
// @param file FileInfo 文件信息
// @param content io.Reader 文件内容
// @return result ScanResult 扫描结果
// @return err error 扫描错误
func (f ScannerFunc) Scan(ctx context.Context, file FileInfo, content io.Reader) (result ScanResult, err error) {
	// 空函数不能执行扫描，返回配置错误而不是触发运行期异常。
	if f == nil {
		return ScanResult{}, fmt.Errorf("%w: scanner function is nil", ErrInvalidConfig)
	}
	// 调用已经确认存在的扫描方法。
	return f(ctx, file, content)
}

// Inspector 定义调用方特有文件结构的检查扩展。
type Inspector interface {
	// Inspect 检查一个从起点开始的文件流。
	Inspect(ctx context.Context, file FileInfo, content io.Reader) error
}

// InspectorFunc 将普通方法适配为 Inspector。
type InspectorFunc func(ctx context.Context, file FileInfo, content io.Reader) error

// Inspect 执行适配后的内容检查方法。
// @param ctx context.Context 调用上下文
// @param file FileInfo 文件信息
// @param content io.Reader 文件内容
// @return err error 检查错误
func (f InspectorFunc) Inspect(ctx context.Context, file FileInfo, content io.Reader) error {
	// 空函数不能执行检查，返回配置错误而不是触发运行期异常。
	if f == nil {
		return fmt.Errorf("%w: inspector function is nil", ErrInvalidConfig)
	}
	// 调用已经确认存在的检查方法。
	return f(ctx, file, content)
}
