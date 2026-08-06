package uploadkit

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultMaxConcurrency = 8 // defaultMaxConcurrency 默认并行上传数
)

// KeyInput 描述对象键生成需要的可信信息。
type KeyInput struct {
	Prefix         string    // Prefix 调用方指定的受信任目录前缀
	OriginalName   string    // OriginalName 清理后的原始名称
	MIMEType       string    // MIMEType 真实文件类型
	Size           int64     // Size 实际文件大小
	ChecksumSHA256 string    // ChecksumSHA256 文件 SHA-256
	CreatedAt      time.Time // CreatedAt 当前 UTC 时间
}

// KeyGenerator 创建对象存储键。
type KeyGenerator func(input KeyInput) (string, error)

// ErrorHandler 接收不改变上传结果的资源清理错误。
type ErrorHandler func(err error)

// Option 修改 Uploader 初始化配置。
type Option func(*uploaderConfig) error

// uploaderConfig 保存 Uploader 的初始化参数。
type uploaderConfig struct {
	tempDir        string           // tempDir 隔离文件目录
	maxConcurrency int              // maxConcurrency 并行上传上限
	defaultPolicy  Policy           // defaultPolicy 未指定请求策略时使用的默认策略
	keyGenerator   KeyGenerator     // keyGenerator 对象键生成器
	scanners       []Scanner        // scanners 病毒扫描器
	inspectors     []Inspector      // inspectors 自定义内容检查器
	cleanupHandler ErrorHandler     // cleanupHandler 临时文件清理错误处理器
	now            func() time.Time // now 提供当前时间
}

// defaultUploaderConfig 返回安全默认配置。
// @return result uploaderConfig 默认配置
func defaultUploaderConfig() uploaderConfig {
	// 使用受控并发、随机对象键和系统时间作为默认行为。
	return uploaderConfig{
		maxConcurrency: defaultMaxConcurrency,
		defaultPolicy:  DefaultPolicy(),
		keyGenerator:   DefaultKeyGenerator,
		now:            time.Now,
	}
}

// WithDefaultPolicy 设置当前 Uploader 的默认上传策略。
// @param policy Policy 默认上传策略
// @return option Option 配置项
func WithDefaultPolicy(policy Policy) Option {
	// 返回延迟应用的默认策略配置方法。
	return func(config *uploaderConfig) error {
		// 默认策略必须由 NewPolicy 或 DefaultPolicy 正确构建。
		if !policy.valid() {
			return ErrInvalidPolicy
		}
		// 保存主项目提供的默认上传策略。
		config.defaultPolicy = policy
		// 配置应用完成。
		return nil
	}
}

// WithTempDir 设置隔离文件目录。
// @param directory string 临时目录，空值使用系统目录
// @return option Option 配置项
func WithTempDir(directory string) Option {
	// 返回延迟应用的配置方法，保持 New 的初始化入口统一。
	return func(config *uploaderConfig) error {
		// 清除目录两端空白，空值表示沿用操作系统临时目录。
		config.tempDir = strings.TrimSpace(directory)
		// 当前配置不存在额外校验错误。
		return nil
	}
}

// WithMaxConcurrency 设置单个 Uploader 最大并行任务数。
// @param maxConcurrency int 最大并行数
// @return option Option 配置项
func WithMaxConcurrency(maxConcurrency int) Option {
	// 返回延迟应用的并发配置方法。
	return func(config *uploaderConfig) error {
		// 非正数无法构建有效的并发信号量。
		if maxConcurrency <= 0 {
			return fmt.Errorf("%w: max concurrency must be greater than zero", ErrInvalidConfig)
		}
		// 保存经过校验的并发上限。
		config.maxConcurrency = maxConcurrency
		// 配置应用完成。
		return nil
	}
}

// WithCleanupErrorHandler 设置临时文件清理错误处理器。
// @description 对象写入成功后，临时文件清理失败不会改变上传结果，可通过该处理器记录异常
// @param handler ErrorHandler 错误处理器
// @return option Option 配置项
func WithCleanupErrorHandler(handler ErrorHandler) Option {
	// 返回延迟应用的清理错误配置方法。
	return func(config *uploaderConfig) error {
		// 空处理器无法接收资源清理异常。
		if handler == nil {
			return fmt.Errorf("%w: cleanup error handler is nil", ErrInvalidConfig)
		}
		// 保存调用方提供的错误处理器。
		config.cleanupHandler = handler
		// 配置应用完成。
		return nil
	}
}

// WithKeyGenerator 设置对象键生成方法。
// @param generator KeyGenerator 对象键生成器
// @return option Option 配置项
func WithKeyGenerator(generator KeyGenerator) Option {
	// 返回延迟应用的对象键配置方法。
	return func(config *uploaderConfig) error {
		// 对象键生成器是上传流程的必需依赖。
		if generator == nil {
			return fmt.Errorf("%w: key generator is nil", ErrInvalidConfig)
		}
		// 保存调用方提供的对象键生成器。
		config.keyGenerator = generator
		// 配置应用完成。
		return nil
	}
}

// WithScanner 注册病毒或恶意内容扫描器。
// @param scanner Scanner 扫描器
// @return option Option 配置项
func WithScanner(scanner Scanner) Option {
	// 返回延迟应用的扫描器注册方法。
	return func(config *uploaderConfig) error {
		// 空扫描器会在上传阶段产生不可恢复的调用错误。
		if scanner == nil {
			return fmt.Errorf("%w: scanner is nil", ErrInvalidConfig)
		}
		// 接口中保存的空函数也必须在初始化阶段拒绝。
		if scannerFunc, matched := scanner.(ScannerFunc); matched && scannerFunc == nil {
			return fmt.Errorf("%w: scanner function is nil", ErrInvalidConfig)
		}
		// 按注册顺序保存扫描器，上传时依次执行。
		config.scanners = append(config.scanners, scanner)
		// 配置应用完成。
		return nil
	}
}

// WithInspector 注册自定义文件结构检查器。
// @param inspector Inspector 内容检查器
// @return option Option 配置项
func WithInspector(inspector Inspector) Option {
	// 返回延迟应用的检查器注册方法。
	return func(config *uploaderConfig) error {
		// 空检查器会在上传阶段产生不可恢复的调用错误。
		if inspector == nil {
			return fmt.Errorf("%w: inspector is nil", ErrInvalidConfig)
		}
		// 接口中保存的空函数也必须在初始化阶段拒绝。
		if inspectorFunc, matched := inspector.(InspectorFunc); matched && inspectorFunc == nil {
			return fmt.Errorf("%w: inspector function is nil", ErrInvalidConfig)
		}
		// 按注册顺序保存检查器，上传时依次执行。
		config.inspectors = append(config.inspectors, inspector)
		// 配置应用完成。
		return nil
	}
}
