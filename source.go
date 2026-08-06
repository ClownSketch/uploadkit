package uploadkit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Source 表示一次上传的数据来源。
// Source 只保证单次 Upload 调用期间可打开，不要求支持并发复用。
type Source interface {
	// Name 返回用于审计和扩展名校验的原始名称。
	Name() string
	// Size 返回已知字节数；未知时返回 -1。
	Size() int64
	// Open 打开一个从内容起点开始读取的数据流。
	Open(ctx context.Context) (io.ReadCloser, error)
}

// source 保存通用 Source 实现需要的数据。
type source struct {
	name string                                       // name 保存来源名称
	size int64                                        // size 保存声明大小
	open func(context.Context) (io.ReadCloser, error) // open 创建读取流
}

// Name 返回来源名称。
// @return name string 来源名称
func (s *source) Name() string {
	// 空来源没有可用名称。
	if s == nil {
		return ""
	}
	// 返回构造来源时保存的净化名称。
	return s.name
}

// Size 返回来源声明大小。
// @return size int64 声明字节数，未知为 -1
func (s *source) Size() int64 {
	// 空来源使用 -1 表示大小未知。
	if s == nil {
		return -1
	}
	// 返回来源声明的字节数。
	return s.size
}

// Open 打开来源数据流。
// @param ctx context.Context 调用上下文
// @return reader io.ReadCloser 数据流
// @return err error 打开错误
func (s *source) Open(ctx context.Context) (reader io.ReadCloser, err error) {
	// 来源或打开方法为空时无法创建数据流。
	if s == nil || s.open == nil {
		return nil, ErrNilSource
	}
	// 所有来源统一要求调用方提供上下文。
	if ctx == nil {
		return nil, ErrNilContext
	}
	// 已经取消的调用不再打开底层资源。
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// 调用具体来源的打开方法。
	return s.open(ctx)
}

// FromMultipart 将标准 multipart 文件头适配为 Source。
// @param file *multipart.FileHeader multipart 文件头
// @return result Source 文件来源
// @return err error 参数错误
func FromMultipart(file *multipart.FileHeader) (result Source, err error) {
	// 空文件头无法提供名称、大小和内容流。
	if file == nil {
		return nil, ErrNilSource
	}
	// 保存 multipart 元数据，并将文件打开动作延迟到上传阶段。
	return &source{
		name: cleanSourceName(file.Filename),
		size: file.Size,
		open: func(context.Context) (io.ReadCloser, error) {
			// 每次打开都交给 multipart 实现创建独立读取流。
			reader, openErr := file.Open()
			// 保留 multipart 底层打开错误。
			if openErr != nil {
				return nil, fmt.Errorf("open multipart source: %w", openErr)
			}
			// 返回由上传流程负责关闭的数据流。
			return reader, nil
		},
	}, nil
}

// FromBytes 将内存字节适配为可重复打开的 Source。
// @param name string 文件名称
// @param data []byte 文件内容
// @return result Source 文件来源
func FromBytes(name string, data []byte) Source {
	// 复制输入，避免调用方上传期间修改底层字节。
	content := append([]byte(nil), data...)
	// 内存来源可以通过新的 Reader 重复打开。
	return &source{
		name: cleanSourceName(name),
		size: int64(len(content)),
		open: func(context.Context) (io.ReadCloser, error) {
			// 每次调用都从字节切片起点创建读取器。
			return io.NopCloser(bytes.NewReader(content)), nil
		},
	}
}

// FromReader 将一次性 Reader 适配为 Source。
// @description 同一个返回值只能执行一次 Upload；已实现 io.Closer 的 Reader 由上传器关闭。
// @param name string 文件名称
// @param size int64 声明大小，未知传 -1
// @param reader io.Reader 数据来源
// @return result Source 文件来源
// @return err error 参数错误
func FromReader(name string, size int64, reader io.Reader) (result Source, err error) {
	// 空 Reader 无法构造上传来源。
	if reader == nil {
		return nil, ErrNilSource
	}
	// 只允许 -1 表示未知大小。
	if size < -1 {
		return nil, fmt.Errorf("%w: declared size=%d", ErrInvalidSource, size)
	}
	// mutex 保护一次性消费标记，避免并发重复打开。
	var mutex sync.Mutex
	// consumed 记录底层 Reader 是否已经交给上传流程。
	consumed := false
	// 一次性来源只延迟移交底层 Reader，不复制数据。
	return &source{
		name: cleanSourceName(name),
		size: size,
		open: func(context.Context) (io.ReadCloser, error) {
			// 串行检查和更新一次性消费状态。
			mutex.Lock()
			defer mutex.Unlock()
			// 已经打开过的 Reader 不能再次从起点读取。
			if consumed {
				return nil, ErrSourceConsumed
			}
			// 在返回 Reader 前立即标记为已消费。
			consumed = true
			// 底层实现带关闭能力时直接转交所有权。
			if closer, ok := reader.(io.ReadCloser); ok {
				return closer, nil
			}
			// 普通 Reader 使用无操作关闭包装器统一接口。
			return io.NopCloser(reader), nil
		},
	}, nil
}

// FromReadSeeker 将可回退 Reader 适配为 Source。
// @param name string 文件名称
// @param size int64 声明大小，未知传 -1
// @param reader io.ReadSeeker 数据来源
// @return result Source 文件来源
// @return err error 参数错误
func FromReadSeeker(name string, size int64, reader io.ReadSeeker) (result Source, err error) {
	// 空 ReadSeeker 无法构造上传来源。
	if reader == nil {
		return nil, ErrNilSource
	}
	// 只允许 -1 表示未知大小。
	if size < -1 {
		return nil, fmt.Errorf("%w: declared size=%d", ErrInvalidSource, size)
	}
	// readToken 串行化共享 ReadSeeker，并允许等待中的调用响应上下文取消。
	readToken := make(chan struct{}, 1)
	// 初始令牌表示底层 Reader 当前可用。
	readToken <- struct{}{}
	// 可回退来源在每次打开前恢复到底层流起点。
	return &source{
		name: cleanSourceName(name),
		size: size,
		open: func(ctx context.Context) (io.ReadCloser, error) {
			// 等待共享 Reader 可用，同时响应调用方取消。
			select {
			case <-readToken:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			// 每次打开都将读取位置恢复到首字节。
			if _, seekErr := reader.Seek(0, io.SeekStart); seekErr != nil {
				// 回退失败时立即释放共享 Reader。
				readToken <- struct{}{}
				return nil, fmt.Errorf("rewind source: %w", seekErr)
			}
			// 关闭包装器只释放读取权，不关闭调用方持有的底层 Reader。
			return &lockedReadSeekCloser{ReadSeeker: reader, readToken: readToken}, nil
		},
	}, nil
}

// FromPath 将本地文件路径适配为可重复打开的 Source。
// @param filePath string 本地文件路径
// @return result Source 文件来源
// @return err error 文件检查错误
func FromPath(filePath string) (result Source, err error) {
	// 清除调用方路径两端空白。
	filePath = strings.TrimSpace(filePath)
	// 空路径不能定位本地文件。
	if filePath == "" {
		return nil, ErrNilSource
	}
	// 提前读取文件信息，确认类型和声明大小。
	info, err := os.Stat(filePath)
	// 文件不存在或不可访问时保留系统错误。
	if err != nil {
		return nil, fmt.Errorf("stat source file: %w", err)
	}
	// 目录、设备和管道不能作为可重复打开的本地文件来源。
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: source is not a regular file", ErrNilSource)
	}
	// 上传时重新打开文件，避免长期占用文件描述符。
	return &source{
		name: cleanSourceName(info.Name()),
		size: info.Size(),
		open: func(context.Context) (io.ReadCloser, error) {
			// 每次上传创建独立文件描述符和读取位置。
			file, openErr := os.Open(filePath)
			// 文件在构造后可能被删除或失去权限，需要返回实时错误。
			if openErr != nil {
				return nil, fmt.Errorf("open source file: %w", openErr)
			}
			// 返回由上传流程负责关闭的文件句柄。
			return file, nil
		},
	}, nil
}

// FromFile 将本地文件对象适配为 Source。
// @description 文件必须拥有可重新打开的真实路径，调用方仍负责关闭原始文件。
// @param file *os.File 本地文件
// @return result Source 文件来源
// @return err error 文件检查错误
func FromFile(file *os.File) (result Source, err error) {
	// 空文件对象无法提供真实路径。
	if file == nil {
		return nil, ErrNilSource
	}
	// 通过真实路径重新构造来源，不接管调用方文件句柄。
	return FromPath(file.Name())
}

// FromFS 将 fs.FS 中的文件适配为可重复打开的 Source。
// @param fileSystem fs.FS 文件系统
// @param fileName string 文件名称
// @return result Source 文件来源
// @return err error 文件检查错误
func FromFS(fileSystem fs.FS, fileName string) (result Source, err error) {
	// 文件系统或名称为空时无法定位文件。
	if fileSystem == nil || strings.TrimSpace(fileName) == "" {
		return nil, ErrNilSource
	}
	// 从抽象文件系统读取文件信息。
	info, err := fs.Stat(fileSystem, fileName)
	// 文件不存在或不可访问时保留底层错误。
	if err != nil {
		return nil, fmt.Errorf("stat fs source: %w", err)
	}
	// 只允许可重复读取的普通文件。
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: source is not a regular file", ErrNilSource)
	}
	// 保存文件事实，并将打开动作延迟到上传阶段。
	return &source{
		name: cleanSourceName(info.Name()),
		size: info.Size(),
		open: func(context.Context) (io.ReadCloser, error) {
			// 每次上传都从抽象文件系统重新打开文件。
			file, openErr := fileSystem.Open(fileName)
			// 文件在构造后可能变化，需要返回实时打开错误。
			if openErr != nil {
				return nil, fmt.Errorf("open fs source: %w", openErr)
			}
			// 返回由上传流程负责关闭的文件流。
			return file, nil
		},
	}, nil
}

// lockedReadSeekCloser 在一次读取完成后释放共享 ReadSeeker。
type lockedReadSeekCloser struct {
	io.ReadSeeker                 // ReadSeeker 调用方持有的底层数据来源
	readToken     chan<- struct{} // readToken 归还共享 Reader 的使用权
	closeOnce     sync.Once       // closeOnce 保证重复关闭只归还一次令牌
}

// Close 释放当前读取权并保留调用方对底层 Reader 的所有权。
// @return err error 始终为空
func (r *lockedReadSeekCloser) Close() error {
	// 重复关闭不能重复释放互斥锁。
	if r != nil && r.readToken != nil {
		r.closeOnce.Do(func() {
			// 归还共享 Reader 的唯一使用令牌。
			r.readToken <- struct{}{}
		})
	}
	// 底层 ReadSeeker 的生命周期仍由调用方管理。
	return nil
}

// cleanSourceName 删除客户端路径，只保留用于展示和校验的文件名。
// @param name string 原始名称
// @return result string 清理后名称
func cleanSourceName(name string) string {
	// 将 Windows 路径分隔符转换为标准形式。
	name = strings.ReplaceAll(name, "\\", "/")
	// 去除目录部分和名称两端空白。
	name = strings.TrimSpace(filepath.Base(name))
	// 目录占位符不能作为文件名称。
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	// 删除控制字符，保留正常 Unicode 文件名。
	return strings.Map(func(character rune) rune {
		// 控制字符可能破坏协议头、日志和管理页面展示。
		if character < 0x20 || character == 0x7f {
			return -1
		}
		// 其他字符按原值保留。
		return character
	}, name)
}
