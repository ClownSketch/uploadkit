package uploadkit

import "errors"

var (
	// ErrNilStore 表示没有提供对象存储适配器。
	ErrNilStore = errors.New("uploadkit: store is nil")
	// ErrNilSource 表示没有提供上传内容来源。
	ErrNilSource = errors.New("uploadkit: source is nil")
	// ErrInvalidSource 表示上传来源返回了无效的大小或内容流。
	ErrInvalidSource = errors.New("uploadkit: invalid source")
	// ErrNilContext 表示调用方没有提供上下文。
	ErrNilContext = errors.New("uploadkit: context is nil")
	// ErrInvalidConfig 表示上传器初始化配置无效。
	ErrInvalidConfig = errors.New("uploadkit: invalid config")
	// ErrInvalidPolicy 表示文件策略配置无效。
	ErrInvalidPolicy = errors.New("uploadkit: invalid policy")
	// ErrSourceConsumed 表示一次性 Reader 来源已经被打开过。
	ErrSourceConsumed = errors.New("uploadkit: source has already been consumed")
	// ErrEmptyFile 表示文件没有任何内容。
	ErrEmptyFile = errors.New("uploadkit: file is empty")
	// ErrFileTooLarge 表示文件实际大小超过策略限制。
	ErrFileTooLarge = errors.New("uploadkit: file is too large")
	// ErrMIMETypeNotAllowed 表示真实文件类型不在策略允许列表中。
	ErrMIMETypeNotAllowed = errors.New("uploadkit: MIME type is not allowed")
	// ErrExtensionMismatch 表示文件扩展名与真实内容类型不一致。
	ErrExtensionMismatch = errors.New("uploadkit: file extension does not match content")
	// ErrUnsafeSVG 表示 SVG 包含脚本、事件或外部资源。
	ErrUnsafeSVG = errors.New("uploadkit: unsafe SVG content")
	// ErrUnsafeArchive 表示压缩包结构、大小或内容不安全。
	ErrUnsafeArchive = errors.New("uploadkit: unsafe archive content")
	// ErrImageDimensions 表示图片尺寸超过策略限制或结构无法解析。
	ErrImageDimensions = errors.New("uploadkit: invalid or oversized image dimensions")
	// ErrScannerRequired 表示策略要求病毒扫描，但上传器没有注册扫描器。
	ErrScannerRequired = errors.New("uploadkit: malware scanner is required")
	// ErrThreatDetected 表示扫描器发现病毒或其他威胁。
	ErrThreatDetected = errors.New("uploadkit: malware or threat detected")
	// ErrInvalidObjectKey 表示生成的对象键为空或尝试越过存储目录。
	ErrInvalidObjectKey = errors.New("uploadkit: invalid object key")
	// ErrObjectExists 表示对象键已经存在，存储拒绝覆盖。
	ErrObjectExists = errors.New("uploadkit: object already exists")
	// ErrTooManyFiles 表示批量上传文件数超过策略限制。
	ErrTooManyFiles = errors.New("uploadkit: too many files")
	// ErrBatchFailed 表示批量上传中至少有一个文件处理失败。
	ErrBatchFailed = errors.New("uploadkit: batch contains failed uploads")
	// ErrSignedURLUnsupported 表示当前存储不支持临时签名地址。
	ErrSignedURLUnsupported = errors.New("uploadkit: signed URL is not supported")
	// ErrHealthCheckUnsupported 表示当前存储没有提供主动健康检查。
	ErrHealthCheckUnsupported = errors.New("uploadkit: health check is not supported")
)
