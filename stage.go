package uploadkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gabriel-vasile/mimetype"
)

const copyBufferSize = 64 << 10 // copyBufferSize 隔离文件流式复制缓冲区

var copyBufferPool = sync.Pool{
	// New 只在池中没有可复用缓冲区时分配内存。
	New: func() any {
		// 每个缓冲区固定为 64KB，兼顾复制吞吐和并发内存占用。
		buffer := make([]byte, copyBufferSize)
		// 返回切片指针，避免 interface 保存切片时产生额外复制。
		return &buffer
	},
}

// stagedFile 保存一次上传的有界隔离文件。
type stagedFile struct {
	file         *os.File // file 保存只对本次上传可见的临时文件
	path         string   // path 保存清理使用的临时路径
	size         int64    // size 保存实际文件大小
	mimeType     string   // mimeType 保存内容识别结果
	checksum     string   // checksum 保存 SHA-256 十六进制值
	originalName string   // originalName 保存清理后的来源名称
}

// stageSource 将来源写入受大小限制的本地隔离文件。
// @param ctx context.Context 调用上下文
// @param source Source 文件来源
// @param policy Policy 上传策略
// @param tempDir string 隔离目录
// @return result *stagedFile 隔离文件
// @return err error 读取、大小或临时文件错误
func stageSource(ctx context.Context, source Source, policy Policy, tempDir string) (result *stagedFile, err error) {
	// 上传来源是隔离流程的必需输入。
	if source == nil {
		return nil, ErrNilSource
	}
	// 读取来源声明大小，用于在打开数据流前快速拒绝明显无效输入。
	declaredSize := source.Size()
	// 只允许 -1 表示未知大小，其他负数属于无效来源。
	if declaredSize < -1 {
		return nil, fmt.Errorf("%w: declared size=%d", ErrInvalidSource, declaredSize)
	}
	// 已知大小为零时直接拒绝空文件。
	if declaredSize == 0 {
		return nil, ErrEmptyFile
	}
	// 声明大小超过策略时不再读取来源内容。
	if declaredSize > policy.maxFileSize {
		return nil, fmt.Errorf("%w: declared=%d max=%d", ErrFileTooLarge, declaredSize, policy.maxFileSize)
	}
	// 打开本次上传使用的数据流。
	reader, err := source.Open(ctx)
	// 来源打开失败时保留原始错误链。
	if err != nil {
		return nil, err
	}
	// 自定义来源不能在成功打开后返回空内容流。
	if reader == nil {
		return nil, fmt.Errorf("%w: opened reader is nil", ErrInvalidSource)
	}
	// 数据流所有权在本次隔离完成后归还。
	defer func() {
		// 关闭失败表示来源未完整收尾，不再向存储层提交内容。
		if closeErr := reader.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close upload source: %w", closeErr))
			// 隔离文件已生成时立即清理，避免关闭错误留下临时文件。
			if result != nil {
				err = errors.Join(err, result.close())
				result = nil
			}
		}
	}()

	// 在指定隔离目录创建仅供本次上传使用的临时文件。
	file, err := os.CreateTemp(tempDir, "uploadkit-*")
	// 临时文件创建失败时不读取来源内容。
	if err != nil {
		return nil, fmt.Errorf("create upload quarantine file: %w", err)
	}
	// 保存清理路径和经过净化的来源名称。
	result = &stagedFile{file: file, path: file.Name(), originalName: cleanSourceName(source.Name())}
	// complete 标记隔离文件是否已经完成全部检查前准备。
	complete := false
	// 任一步骤失败都关闭并删除未完成的隔离文件。
	defer func() {
		if !complete {
			// 清理失败必须进入原始错误链，避免隔离文件泄漏后没有观测信息。
			if closeErr := result.close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
			// 失败结果不向调用方暴露已经清理的临时文件。
			result = nil
		}
	}()

	// 在复制内容的同时计算文件 SHA-256。
	hasher := sha256.New()
	// 多读取一个字节，用于准确识别实际大小是否超过上限。
	limited := &io.LimitedReader{R: reader, N: policy.maxFileSize + 1}
	// 从缓冲池获取当前复制任务使用的内存。
	bufferPointer := copyBufferPool.Get().(*[]byte)
	// 解引用为 io.Copy 循环使用的字节切片。
	buffer := *bufferPointer
	// 复制完成后将缓冲区归还池中。
	defer copyBufferPool.Put(bufferPointer)
	// 同时写入隔离文件和哈希计算器，并在循环中检查上下文。
	written, err := copyWithContext(ctx, io.MultiWriter(file, hasher), limited, buffer)
	// 读取或写入失败时终止当前上传。
	if err != nil {
		return nil, fmt.Errorf("stage upload source: %w", err)
	}
	// 实际没有读取到内容时拒绝上传。
	if written == 0 {
		return nil, ErrEmptyFile
	}
	// 实际字节数超过策略时拒绝上传，不信任来源声明大小。
	if written > policy.maxFileSize {
		return nil, fmt.Errorf("%w: actual=%d max=%d", ErrFileTooLarge, written, policy.maxFileSize)
	}
	// 保存后续存储和检查使用的真实文件大小。
	result.size = written
	// 保存十六进制 SHA-256，供完整性校验和对象元数据使用。
	result.checksum = hex.EncodeToString(hasher.Sum(nil))
	// MIME 识别前将文件指针回退到内容起点。
	if err = result.seekStart(); err != nil {
		return nil, err
	}
	// 直接根据文件内容识别 MIME，不读取客户端声明值。
	detected, err := mimetype.DetectReader(file)
	// MIME 识别失败时不能继续进入存储阶段。
	if err != nil {
		return nil, fmt.Errorf("detect upload MIME type: %w", err)
	}
	// 清除 MIME 参数并保存规范类型。
	result.mimeType = normalizeMIMEType(detected.String())
	// 为后续结构检查再次回退文件指针。
	if err = result.seekStart(); err != nil {
		return nil, err
	}
	// 标记隔离阶段完成，错误清理逻辑不再提前释放结果。
	complete = true
	// 返回由调用方负责关闭的隔离文件。
	return result, nil
}

// seekStart 将隔离文件回退到内容起点。
// @return err error 文件回退错误
func (s *stagedFile) seekStart() error {
	// 隔离文件不存在时返回明确的来源错误。
	if s == nil || s.file == nil {
		return ErrNilSource
	}
	// 将文件偏移恢复到首字节。
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind staged upload: %w", err)
	}
	// 文件已经可以从起点读取。
	return nil
}

// info 返回扫描和检查使用的文件信息。
// @return result FileInfo 文件信息
func (s *stagedFile) info() FileInfo {
	// 只暴露已经通过隔离阶段确认的文件事实。
	return FileInfo{
		OriginalName:   s.originalName,
		MIMEType:       s.mimeType,
		Size:           s.size,
		ChecksumSHA256: s.checksum,
	}
}

// contentReader 返回限制在真实文件大小内的只读内容视图。
// @return result io.Reader 只读文件内容
// @return err error 隔离文件不可用错误
func (s *stagedFile) contentReader() (result io.Reader, err error) {
	// 隔离文件必须保持打开状态才能创建独立读取视图。
	if s == nil || s.file == nil {
		return nil, ErrNilSource
	}
	// SectionReader 不暴露写入能力，也不会共享可变读取偏移。
	return io.NewSectionReader(s.file, 0, s.size), nil
}

// close 关闭并删除隔离文件。
// @return err error 关闭或删除错误
func (s *stagedFile) close() error {
	// 重复清理空对象时直接视为成功。
	if s == nil {
		return nil
	}
	// result 聚合关闭和删除两个阶段的错误。
	var result error
	// 先关闭文件句柄，确保 Windows 等环境允许删除文件。
	if s.file != nil {
		// 关闭失败仍继续尝试删除临时文件。
		if err := s.file.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close staged upload: %w", err))
		}
		// 清空文件引用，保证重复调用不会再次关闭。
		s.file = nil
	}
	// 临时路径存在时执行文件删除。
	if s.path != "" {
		// 文件已经不存在时视为清理完成。
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove staged upload: %w", err))
		}
		// 清空路径，保证重复调用保持幂等。
		s.path = ""
	}
	// 返回清理阶段聚合错误。
	return result
}

// copyWithContext 分块复制内容并及时响应上下文取消。
// @param ctx context.Context 调用上下文
// @param destination io.Writer 写入目标
// @param source io.Reader 数据来源
// @param buffer []byte 复用缓冲区
// @return written int64 实际写入字节数
// @return err error 上下文、读取或写入错误
func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader, buffer []byte) (written int64, err error) {
	// 持续复制直到读取完成、上下文取消或发生读写错误。
	for {
		// 每次读取前检查取消信号，避免长文件无法及时终止。
		if err = ctx.Err(); err != nil {
			return written, err
		}
		// 从来源读取一个固定大小的数据块。
		readCount, readErr := source.Read(buffer)
		// 只在本轮读取到数据时执行写入。
		if readCount > 0 {
			// 将当前数据块完整写入目标。
			writeCount, writeErr := destination.Write(buffer[:readCount])
			// 累加已经成功写入的实际字节数。
			written += int64(writeCount)
			// 写入错误优先返回，保留已写入数量。
			if writeErr != nil {
				return written, writeErr
			}
			// 无错误但写入数量不足时返回标准短写错误。
			if writeCount != readCount {
				return written, io.ErrShortWrite
			}
		}
		// 当前读取返回状态时处理完成或错误分支。
		if readErr != nil {
			// EOF 表示全部内容已经安全复制。
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			// 其他读取错误保留已写入数量并返回。
			return written, readErr
		}
	}
}
