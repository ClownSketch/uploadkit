package uploadkit

import (
	"mime"
	"slices"
	"strings"
)

const (
	mimeSVG = "image/svg+xml"   // mimeSVG 表示 SVG 主动图片内容
	mimeZIP = "application/zip" // mimeZIP 表示 ZIP 归档内容
)

// archiveMIMETypes 保存需要归档结构检查的常见 MIME 类型。
var archiveMIMETypes = []string{
	"application/gzip",
	"application/java-archive",
	"application/vnd.android.package-archive",
	"application/vnd.ms-cab-compressed",
	"application/vnd.rar",
	"application/x-7z-compressed",
	"application/x-bzip2",
	"application/x-compress",
	"application/x-lzip",
	"application/x-rar-compressed",
	"application/x-tar",
	"application/x-xz",
	"application/zstd",
	mimeZIP,
}

// zipContainerMIMETypes 保存使用 ZIP 作为内部容器的常见文件类型。
var zipContainerMIMETypes = []string{
	mimeZIP,
	"application/epub+zip",
	"application/java-archive",
	"application/vnd.android.package-archive",
	"application/vnd.google-earth.kmz",
	"application/vnd.ms-visio.drawing",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

// knownExtensions 保存稳定的 MIME 与扩展名映射，避免依赖操作系统注册表差异。
var knownExtensions = map[string][]string{
	"application/gzip":              {".gz"},
	"application/json":              {".json"},
	"application/msword":            {".doc"},
	"application/pdf":               {".pdf"},
	"application/vnd.ms-excel":      {".xls"},
	"application/vnd.ms-powerpoint": {".ppt"},
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         {".xlsx"},
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   {".docx"},
	"application/vnd.rar":          {".rar"},
	"application/x-7z-compressed":  {".7z"},
	"application/x-rar-compressed": {".rar"},
	"application/x-tar":            {".tar"},
	mimeZIP:                        {".zip"},
	"audio/aac":                    {".aac"},
	"audio/flac":                   {".flac"},
	"audio/mpeg":                   {".mp3"},
	"audio/ogg":                    {".ogg"},
	"audio/wav":                    {".wav"},
	"image/bmp":                    {".bmp"},
	"image/gif":                    {".gif"},
	"image/jpeg":                   {".jpg", ".jpeg"},
	"image/png":                    {".png"},
	mimeSVG:                        {".svg"},
	"image/vnd.microsoft.icon":     {".ico"},
	"image/webp":                   {".webp"},
	"text/csv":                     {".csv"},
	"text/plain":                   {".txt"},
	"video/mp4":                    {".mp4"},
	"video/quicktime":              {".mov"},
	"video/webm":                   {".webm"},
	"video/x-msvideo":              {".avi"},
}

// normalizeMIMEType 去除 MIME 参数并统一为小写。
// @param value string MIME 原始值
// @return result string 规范 MIME 类型
func normalizeMIMEType(value string) string {
	// MIME 类型比较统一使用小写并忽略两端空白。
	value = strings.TrimSpace(strings.ToLower(value))
	// 分号后的字符集和边界参数不参与类型判断。
	if separator := strings.IndexByte(value, ';'); separator >= 0 {
		value = strings.TrimSpace(value[:separator])
	}
	// 返回不包含参数的规范 MIME 类型。
	return value
}

// extensionsForMIME 返回可信 MIME 对应的规范扩展名。
// @param mimeType string MIME 类型
// @return result []string 扩展名列表
func extensionsForMIME(mimeType string) []string {
	// 内置映射优先，确保各运行环境返回一致结果。
	if extensions, exists := knownExtensions[mimeType]; exists {
		return extensions
	}
	// 未知类型再查询标准库维护的系统映射。
	extensions, err := mime.ExtensionsByType(mimeType)
	// 系统映射查询失败时返回空列表，由调用方只依据 MIME 判断。
	if err != nil {
		return nil
	}
	// 预分配结果容量，减少扩展名过滤过程中的扩容。
	result := make([]string, 0, len(extensions))
	// 只保留安全且未重复的规范扩展名。
	for _, extension := range extensions {
		// 扩展名比较统一使用小写。
		extension = strings.ToLower(extension)
		// 非 ASCII 安全格式和重复项不进入可信列表。
		if isSafeExtension(extension) && !slices.Contains(result, extension) {
			result = append(result, extension)
		}
	}
	// 返回过滤后的扩展名列表。
	return result
}

// safeExtension 返回生成对象键使用的可信扩展名。
// @param mimeType string MIME 类型
// @return result string 扩展名
func safeExtension(mimeType string) string {
	// 查询真实 MIME 对应的可信扩展名。
	extensions := extensionsForMIME(mimeType)
	// 没有可靠映射时使用中性的二进制扩展名。
	if len(extensions) == 0 {
		return ".bin"
	}
	// 使用首个规范扩展名生成对象键。
	return extensions[0]
}

// isSafeExtension 检查扩展名只包含 ASCII 字母和数字。
// @param extension string 文件扩展名
// @return result bool 是否安全
func isSafeExtension(extension string) bool {
	// 扩展名必须包含点号，且长度限制在常见安全范围。
	if len(extension) < 2 || len(extension) > 12 || extension[0] != '.' {
		return false
	}
	// 点号后只允许小写 ASCII 字母和数字。
	for _, character := range extension[1:] {
		// 小写字母属于允许范围。
		if character >= 'a' && character <= 'z' {
			continue
		}
		// 数字属于允许范围。
		if character >= '0' && character <= '9' {
			continue
		}
		// 其他字符可能改变路径或协议语义，直接拒绝。
		return false
	}
	// 所有字符均符合扩展名约束。
	return true
}

// isArchiveMIME 判断 MIME 是否属于归档文件。
// @param mimeType string MIME 类型
// @return result bool 是否为归档文件
func isArchiveMIME(mimeType string) bool {
	// 归档类型列表较小，线性查询避免额外映射开销。
	return slices.Contains(archiveMIMETypes, mimeType)
}

// isZIPContainerMIME 判断文件类型是否需要执行 ZIP 内部结构检查。
// @param mimeType string MIME 类型
// @return result bool 是否为 ZIP 容器
func isZIPContainerMIME(mimeType string) bool {
	// 精确匹配常见 Office、EPUB、JAR 和其他 ZIP 容器。
	if slices.Contains(zipContainerMIMETypes, mimeType) {
		return true
	}
	// OpenDocument 系列共享稳定的 MIME 前缀并统一使用 ZIP 容器。
	return strings.HasPrefix(mimeType, "application/vnd.oasis.opendocument.") ||
		strings.HasPrefix(mimeType, "application/x-vnd.oasis.opendocument.")
}
