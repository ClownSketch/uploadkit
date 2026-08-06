package uploadkit

import (
	"fmt"
	"math"
	"mime"
	"path/filepath"
	"slices"
	"strings"
)

const (
	defaultMaxFileSize         = 10 << 20    // defaultMaxFileSize 默认单文件大小上限
	defaultMaxFiles            = 10          // defaultMaxFiles 默认批量文件数量
	defaultMaxImagePixels      = 100_000_000 // defaultMaxImagePixels 默认图片像素上限
	defaultMaxArchiveFiles     = 1000        // defaultMaxArchiveFiles 默认压缩包文件上限
	defaultMaxArchiveBytes     = 512 << 20   // defaultMaxArchiveBytes 默认解压总大小
	defaultMaxCompressionRatio = 200         // defaultMaxCompressionRatio 默认最大压缩比
)

// defaultAllowedMIMETypes 保存没有业务配置时使用的保守 MIME 允许列表。
var defaultAllowedMIMETypes = []string{
	"application/pdf",
	"image/jpeg",
	"image/png",
	"image/webp",
	"text/plain",
}

// PolicyOptions 定义一个可复用上传策略。
type PolicyOptions struct {
	MaxFileSize             int64    // MaxFileSize 单文件最大实际字节数
	MaxFiles                int      // MaxFiles 单次批量上传最大文件数
	AllowedMIMETypes        []string // AllowedMIMETypes 允许的真实 MIME 类型
	DeniedMIMETypes         []string // DeniedMIMETypes 禁止的真实 MIME 类型，优先于允许规则
	IgnoreExtensionMismatch bool     // IgnoreExtensionMismatch 是否忽略名称扩展名不一致
	AllowNestedArchives     bool     // AllowNestedArchives 是否允许 ZIP 内再次包含归档文件
	RequireMalwareScanner   bool     // RequireMalwareScanner 是否强制执行病毒扫描
	MaxImagePixels          uint64   // MaxImagePixels 图片最大像素数
	MaxArchiveFiles         int      // MaxArchiveFiles ZIP 最大文件数
	MaxArchiveExpandedBytes int64    // MaxArchiveExpandedBytes ZIP 最大解压字节数
	MaxCompressionRatio     float64  // MaxCompressionRatio ZIP 最大压缩比
}

// Policy 保存已经校验和编译完成的只读上传规则。
type Policy struct {
	maxFileSize             int64               // maxFileSize 单文件上限
	maxFiles                int                 // maxFiles 批量数量上限
	allowedMIMETypes        map[string]struct{} // allowedMIMETypes 允许类型集合
	allowedMIMEPrefixes     []string            // allowedMIMEPrefixes 允许类型前缀
	deniedMIMETypes         map[string]struct{} // deniedMIMETypes 禁止类型集合
	deniedMIMEPrefixes      []string            // deniedMIMEPrefixes 禁止类型前缀
	allowAllMIMETypes       bool                // allowAllMIMETypes 是否显式允许全部类型
	denyAllMIMETypes        bool                // denyAllMIMETypes 是否显式禁止全部类型
	ignoreExtensionMismatch bool                // ignoreExtensionMismatch 是否忽略扩展名
	allowNestedArchives     bool                // allowNestedArchives 是否允许嵌套归档
	requireMalwareScanner   bool                // requireMalwareScanner 是否要求扫描器
	maxImagePixels          uint64              // maxImagePixels 图片像素上限
	maxArchiveFiles         int                 // maxArchiveFiles ZIP 文件数上限
	maxArchiveExpandedBytes int64               // maxArchiveExpandedBytes ZIP 解压上限
	maxCompressionRatio     float64             // maxCompressionRatio ZIP 压缩比上限
}

// DefaultPolicy 返回 uploadkit 的保守默认上传策略。
// @return result Policy 默认上传策略
func DefaultPolicy() Policy {
	// 默认参数由 NewPolicy 统一补齐，确保默认策略和自定义策略遵循同一套校验规则。
	result, _ := NewPolicy(PolicyOptions{})
	// 返回只读使用的默认策略。
	return result
}

// NewPolicy 创建不可变上传策略。
// @param options PolicyOptions 策略参数
// @return result Policy 上传策略
// @return err error 参数错误
func NewPolicy(options PolicyOptions) (result Policy, err error) {
	// 零值使用保守的默认单文件大小上限。
	if options.MaxFileSize == 0 {
		options.MaxFileSize = defaultMaxFileSize
	}
	// 单文件上限必须为可安全加一的正整数。
	if options.MaxFileSize < 0 || options.MaxFileSize == math.MaxInt64 {
		return Policy{}, fmt.Errorf("%w: MaxFileSize must be greater than zero", ErrInvalidPolicy)
	}
	// 未提供 MIME 规则时使用 uploadkit 的保守默认允许列表。
	if len(options.AllowedMIMETypes) == 0 {
		options.AllowedMIMETypes = append([]string(nil), defaultAllowedMIMETypes...)
	}
	// 负数文件数量没有有效含义。
	if options.MaxFiles < 0 {
		return Policy{}, ErrInvalidPolicy
	}
	// 零值使用安全的默认批量上限。
	if options.MaxFiles == 0 {
		options.MaxFiles = defaultMaxFiles
	}
	// 零值使用默认图片像素上限。
	if options.MaxImagePixels == 0 {
		options.MaxImagePixels = defaultMaxImagePixels
	}
	// 零值使用默认 ZIP 文件数量上限。
	if options.MaxArchiveFiles == 0 {
		options.MaxArchiveFiles = defaultMaxArchiveFiles
	}
	// 零值使用默认 ZIP 解压总大小上限。
	if options.MaxArchiveExpandedBytes == 0 {
		options.MaxArchiveExpandedBytes = defaultMaxArchiveBytes
	}
	// 零值使用默认最大压缩比。
	if options.MaxCompressionRatio == 0 {
		options.MaxCompressionRatio = defaultMaxCompressionRatio
	}
	// 归档限制必须为有限且可安全计算的非负值。
	if options.MaxArchiveFiles < 0 || options.MaxArchiveExpandedBytes < 0 ||
		options.MaxArchiveExpandedBytes == math.MaxInt64 || options.MaxCompressionRatio < 0 ||
		math.IsNaN(options.MaxCompressionRatio) || math.IsInf(options.MaxCompressionRatio, 0) {
		return Policy{}, ErrInvalidPolicy
	}

	// 编译主项目提供的 MIME 允许规则。
	allowed, allowedPrefixes, allowAll, err := compileMIMERules(options.AllowedMIMETypes)
	if err != nil {
		return Policy{}, err
	}
	// 编译可选的 MIME 禁止规则，禁止规则在上传时优先匹配。
	denied, deniedPrefixes, denyAll, err := compileMIMERules(options.DeniedMIMETypes)
	if err != nil {
		return Policy{}, err
	}
	// 返回只读使用的编译策略，避免每次上传重复解析规则。
	return Policy{
		maxFileSize:             options.MaxFileSize,
		maxFiles:                options.MaxFiles,
		allowedMIMETypes:        allowed,
		allowedMIMEPrefixes:     allowedPrefixes,
		deniedMIMETypes:         denied,
		deniedMIMEPrefixes:      deniedPrefixes,
		allowAllMIMETypes:       allowAll,
		denyAllMIMETypes:        denyAll,
		ignoreExtensionMismatch: options.IgnoreExtensionMismatch,
		allowNestedArchives:     options.AllowNestedArchives,
		requireMalwareScanner:   options.RequireMalwareScanner,
		maxImagePixels:          options.MaxImagePixels,
		maxArchiveFiles:         options.MaxArchiveFiles,
		maxArchiveExpandedBytes: options.MaxArchiveExpandedBytes,
		maxCompressionRatio:     options.MaxCompressionRatio,
	}, nil
}

// compileMIMERules 校验并编译一组完整 MIME 或 type/* 通配规则。
// @param values []string MIME 规则
// @return exact map[string]struct{} 完整 MIME 集合
// @return prefixes []string MIME 前缀列表
// @return all bool 是否匹配全部 MIME
// @return err error 非法规则错误
func compileMIMERules(values []string) (exact map[string]struct{}, prefixes []string, all bool, err error) {
	// 按输入规模预分配精确规则集合和前缀列表。
	exact = make(map[string]struct{}, len(values))
	prefixes = make([]string, 0, len(values))
	// 逐项规范并编译调用方提供的 MIME 规则。
	for _, mimeType := range values {
		// MIME 比较忽略大小写和参数。
		mimeType = normalizeMIMEType(mimeType)
		// 规范化后为空的规则直接拒绝。
		if mimeType == "" {
			return nil, nil, false, fmt.Errorf("%w: MIME rule is empty", ErrInvalidPolicy)
		}
		// */* 只在调用方显式配置时匹配全部真实 MIME。
		if mimeType == "*/*" {
			all = true
			continue
		}
		// type/* 通配规则只允许星号出现在子类型位置。
		if strings.HasSuffix(mimeType, "/*") {
			parts := strings.Split(mimeType, "/")
			if len(parts) != 2 || parts[0] == "" || strings.Contains(parts[0], "*") {
				return nil, nil, false, fmt.Errorf("%w: invalid MIME wildcard=%s", ErrInvalidPolicy, mimeType)
			}
			// 使用标准解析器校验主类型字符是否合法。
			if _, _, parseErr := mime.ParseMediaType(parts[0] + "/placeholder"); parseErr != nil {
				return nil, nil, false, fmt.Errorf("%w: invalid MIME wildcard=%s", ErrInvalidPolicy, mimeType)
			}
			// 去除星号后保存带斜杠的 MIME 前缀。
			prefix := strings.TrimSuffix(mimeType, "*")
			if !slices.Contains(prefixes, prefix) {
				prefixes = append(prefixes, prefix)
			}
			continue
		}
		// 完整 MIME 规则不能在其他位置携带星号。
		if strings.Contains(mimeType, "*") {
			return nil, nil, false, fmt.Errorf("%w: invalid MIME wildcard=%s", ErrInvalidPolicy, mimeType)
		}
		// 完整规则必须符合标准 type/subtype 语法。
		parsedMIME, _, parseErr := mime.ParseMediaType(mimeType)
		if parseErr != nil || parsedMIME != mimeType || strings.Count(mimeType, "/") != 1 {
			return nil, nil, false, fmt.Errorf("%w: invalid MIME type=%s", ErrInvalidPolicy, mimeType)
		}
		// 使用集合保存精确规则并自动消除重复项。
		exact[mimeType] = struct{}{}
	}
	// 返回完成编译的只读规则。
	return exact, prefixes, all, nil
}

// validateType 校验真实 MIME 和原始扩展名。
// @param fileName string 原始文件名
// @param mimeType string 真实 MIME 类型
// @return err error 类型或安全策略错误
func (p Policy) validateType(fileName string, mimeType string) error {
	// 只接受由 NewPolicy 构建的有效策略。
	if !p.valid() {
		return ErrInvalidPolicy
	}
	// 禁止规则优先于允许规则，便于主项目从通配范围中排除指定类型。
	if matchesMIMERules(mimeType, p.deniedMIMETypes, p.deniedMIMEPrefixes, p.denyAllMIMETypes) {
		return fmt.Errorf("%w: %s", ErrMIMETypeNotAllowed, mimeType)
	}
	// 允许规则决定当前真实 MIME 是否可以进入上传链路。
	allowed := matchesMIMERules(mimeType, p.allowedMIMETypes, p.allowedMIMEPrefixes, p.allowAllMIMETypes)
	// 不在允许列表中的真实类型直接拒绝。
	if !allowed {
		return fmt.Errorf("%w: %s", ErrMIMETypeNotAllowed, mimeType)
	}
	// 调用方明确忽略扩展名时不再校验名称。
	if p.ignoreExtensionMismatch {
		return nil
	}
	// 从净化后的原始名称提取小写扩展名。
	extension := strings.ToLower(filepath.Ext(fileName))
	// 无扩展名文件只依据真实 MIME 判断。
	if extension == "" {
		return nil
	}
	// 查询当前真实 MIME 对应的可信扩展名。
	allowedExtensions := extensionsForMIME(mimeType)
	// 已知扩展名映射存在时必须与来源名称一致。
	if len(allowedExtensions) > 0 && !slices.Contains(allowedExtensions, extension) {
		return fmt.Errorf("%w: extension=%s MIME=%s", ErrExtensionMismatch, extension, mimeType)
	}
	// 文件类型和名称校验完成。
	return nil
}

// matchesMIMERules 判断真实 MIME 是否命中规则集合。
// @param mimeType string 真实 MIME
// @param exact map[string]struct{} 完整规则
// @param prefixes []string 前缀规则
// @param all bool 是否匹配全部类型
// @return result bool 是否命中
func matchesMIMERules(mimeType string, exact map[string]struct{}, prefixes []string, all bool) bool {
	// 显式全匹配规则不再执行其他查询。
	if all {
		return true
	}
	// 精确集合提供常见规则的常数时间查询。
	if _, exists := exact[mimeType]; exists {
		return true
	}
	// 通配前缀数量较少，顺序匹配保持实现清晰。
	for _, prefix := range prefixes {
		if strings.HasPrefix(mimeType, prefix) {
			return true
		}
	}
	// 所有规则均未命中。
	return false
}

// valid 判断策略已经由 NewPolicy 正确构建。
// @return result bool 是否有效
func (p Policy) valid() bool {
	// 有效策略必须包含文件上限和至少一条 MIME 允许规则。
	return p.maxFileSize > 0 && (p.allowAllMIMETypes || len(p.allowedMIMETypes) > 0 || len(p.allowedMIMEPrefixes) > 0)
}
