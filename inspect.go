package uploadkit

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/webp"
)

// dangerousSVGElements 保存可能执行脚本或加载外部内容的 SVG 元素。
var dangerousSVGElements = map[string]struct{}{
	"animate": {}, "animatemotion": {}, "animatetransform": {}, "discard": {}, "embed": {},
	"foreignobject": {}, "iframe": {}, "object": {}, "script": {}, "set": {}, "style": {},
}

// nestedArchiveExtensions 保存常见归档扩展名，用于条目名称的第一层检查。
var nestedArchiveExtensions = []string{
	".7z", ".apk", ".bz2", ".cab", ".docx", ".ear", ".epub", ".gz", ".jar", ".odp", ".ods", ".odt",
	".pptx", ".rar", ".tar", ".tgz", ".war", ".xlsx", ".xz", ".zip", ".zst",
}

const archiveEntryProbeSize = 8 << 10 // archiveEntryProbeSize ZIP 条目内容识别字节数

// inspectBuiltIn 执行核心库内置的结构安全检查。
// @param ctx context.Context 调用上下文
// @param staged *stagedFile 隔离文件
// @param policy Policy 上传策略
// @return err error 结构或安全错误
func inspectBuiltIn(ctx context.Context, staged *stagedFile, policy Policy) error {
	// 进入结构检查前先响应调用方取消信号。
	if err := ctx.Err(); err != nil {
		return err
	}
	// SVG 使用 XML 级主动内容检查。
	if staged.mimeType == mimeSVG {
		return inspectSVG(staged)
	}
	// 位图只解析文件头和尺寸，不完整解码像素数据。
	if strings.HasPrefix(staged.mimeType, "image/") {
		return inspectImage(staged, policy.maxImagePixels)
	}
	// ZIP 及 Office、OpenDocument 等 ZIP 容器统一检查内部结构。
	if isZIPContainerMIME(staged.mimeType) {
		// 检查容器条目、解压大小和内部内容类型。
		return inspectZIP(ctx, staged, policy)
	}
	// 其他允许类型没有内置结构检查，由主项目按需注册 Inspector 或 Scanner。
	return nil
}

// inspectImage 解码图片头并限制总像素数。
// @param staged *stagedFile 隔离文件
// @param maxPixels uint64 最大像素数
// @return err error 图片结构或尺寸错误
func inspectImage(staged *stagedFile, maxPixels uint64) error {
	// 图片解析前从文件起点开始读取。
	if err := staged.seekStart(); err != nil {
		return err
	}
	// 只解码图片配置，避免为像素内容分配大块内存。
	config, _, err := image.DecodeConfig(staged.file)
	// 无法识别的图片结构直接拒绝。
	if err != nil {
		return fmt.Errorf("%w: %v", ErrImageDimensions, err)
	}
	// 宽高必须都是有效正数。
	if config.Width <= 0 || config.Height <= 0 {
		return ErrImageDimensions
	}
	// 转为无符号整数后再执行像素乘法。
	width := uint64(config.Width)
	height := uint64(config.Height)
	// 乘法前检查溢出，避免畸形图片绕过像素上限。
	if height != 0 && width > ^uint64(0)/height {
		return ErrImageDimensions
	}
	// 计算图片总像素数量。
	pixels := width * height
	// 启用像素上限时拒绝超大图片。
	if maxPixels > 0 && pixels > maxPixels {
		return fmt.Errorf("%w: width=%d height=%d pixels=%d max=%d", ErrImageDimensions, config.Width, config.Height, pixels, maxPixels)
	}
	// 为后续检查和存储恢复文件偏移。
	return staged.seekStart()
}

// inspectSVG 使用保守规则拒绝脚本、事件处理器和外部资源。
// @param staged *stagedFile 隔离文件
// @return err error SVG 解析或安全错误
func inspectSVG(staged *stagedFile) error {
	// XML 解析前从文件起点开始读取。
	if err := staged.seekStart(); err != nil {
		return err
	}
	// 使用流式 XML 解码器限制内存占用。
	decoder := xml.NewDecoder(staged.file)
	// 顺序检查每一个 XML Token。
	for {
		// 读取下一个 XML Token。
		token, err := decoder.Token()
		// Token 读取状态决定完成或失败分支。
		if err != nil {
			// EOF 表示完整 SVG 已经检查完成。
			if errors.Is(err, io.EOF) {
				return staged.seekStart()
			}
			// XML 结构错误按不安全内容处理。
			return fmt.Errorf("%w: %v", ErrUnsafeSVG, err)
		}
		// XML 样式表和文档指令可能引入外部资源，统一拒绝。
		switch typedToken := token.(type) {
		case xml.ProcInst:
			// XML 声明本身不携带可执行内容，其他处理指令全部拒绝。
			if !strings.EqualFold(typedToken.Target, "xml") {
				return fmt.Errorf("%w: processing instruction=%s", ErrUnsafeSVG, typedToken.Target)
			}
		case xml.Directive:
			// SVG 不需要文档指令即可正常展示，保守拒绝该扩展入口。
			return fmt.Errorf("%w: XML directive", ErrUnsafeSVG)
		}
		// 只对开始元素继续执行元素和属性检查。
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		// 元素名统一使用小写进行匹配。
		elementName := strings.ToLower(start.Name.Local)
		// 脚本和外部内容元素直接拒绝。
		if _, dangerous := dangerousSVGElements[elementName]; dangerous {
			return fmt.Errorf("%w: element=%s", ErrUnsafeSVG, elementName)
		}
		// 逐项检查事件、链接和样式属性。
		for _, attribute := range start.Attr {
			// 属性名统一使用小写进行匹配。
			name := strings.ToLower(attribute.Name.Local)
			// 属性值清除空白并统一为小写。
			value := strings.TrimSpace(strings.ToLower(attribute.Value))
			// on* 属性可能注册浏览器事件处理器。
			if strings.HasPrefix(name, "on") {
				return fmt.Errorf("%w: attribute=%s", ErrUnsafeSVG, name)
			}
			// href 只允许指向当前文档内的片段。
			if name == "href" && value != "" && !strings.HasPrefix(value, "#") {
				return fmt.Errorf("%w: external href", ErrUnsafeSVG)
			}
			// xml:base 和 src 会改变资源解析位置或直接加载外部内容。
			if (name == "base" || name == "src") && value != "" {
				return fmt.Errorf("%w: external resource attribute=%s", ErrUnsafeSVG, name)
			}
			// 行内 CSS 需要完整 CSS 解析器才能可靠验证，当前安全策略直接拒绝。
			if name == "style" && value != "" {
				return fmt.Errorf("%w: inline style", ErrUnsafeSVG)
			}
			// 反斜杠可用于 CSS 转义关键字，不能进入资源相关属性。
			if strings.Contains(value, "\\") {
				return fmt.Errorf("%w: escaped attribute value", ErrUnsafeSVG)
			}
			// 展示属性中的 URL 只允许当前文档片段引用。
			if !safeSVGURLFunctions(value) {
				return fmt.Errorf("%w: external URL function", ErrUnsafeSVG)
			}
		}
	}
}

// safeSVGURLFunctions 检查属性中的 URL 函数只引用当前 SVG 片段。
// @param value string 已规范为小写的属性值
// @return result bool 是否安全
func safeSVGURLFunctions(value string) bool {
	// 持续检查属性中出现的每一个 URL 函数。
	for {
		// 没有剩余 URL 函数时说明当前属性安全。
		start := strings.Index(value, "url(")
		if start < 0 {
			return true
		}
		// 截取 URL 函数参数并确认存在结束括号。
		value = value[start+len("url("):]
		end := strings.IndexByte(value, ')')
		if end < 0 {
			return false
		}
		// 去除 CSS 允许的空白和引号，只接受 #fragment。
		target := strings.Trim(strings.TrimSpace(value[:end]), "\"'")
		if !strings.HasPrefix(target, "#") || len(target) == 1 {
			return false
		}
		// 继续检查当前结束括号之后的剩余属性值。
		value = value[end+1:]
	}
}

// inspectZIP 验证 ZIP 目录、数量、解压大小和压缩比。
// @param ctx context.Context 调用上下文
// @param staged *stagedFile 隔离文件
// @param policy Policy 上传策略
// @return err error ZIP 结构或安全错误
func inspectZIP(ctx context.Context, staged *stagedFile, policy Policy) error {
	// 直接基于隔离文件和真实大小解析 ZIP 中央目录。
	reader, err := zip.NewReader(staged.file, staged.size)
	// 中央目录损坏时拒绝整个归档。
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeArchive, err)
	}
	// 条目数量超过策略上限时不再逐项读取。
	if len(reader.File) > policy.maxArchiveFiles {
		return fmt.Errorf("%w: files=%d max=%d", ErrUnsafeArchive, len(reader.File), policy.maxArchiveFiles)
	}
	// expandedBytes 累加中央目录声明的解压大小。
	var expandedBytes uint64
	// actualExpandedBytes 累加真正读取到的解压字节数。
	var actualExpandedBytes int64
	// 按中央目录顺序检查每个归档条目。
	for _, archiveFile := range reader.File {
		// 每个条目处理前响应调用方取消信号。
		if err = ctx.Err(); err != nil {
			return err
		}
		// ZIP 加密条目无法在当前检查器中验证内容。
		if archiveFile.Flags&0x1 != 0 {
			return fmt.Errorf("%w: encrypted entry=%s", ErrUnsafeArchive, archiveFile.Name)
		}
		// 符号链接可能在解压时逃逸目标目录。
		if archiveFile.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symbolic link=%s", ErrUnsafeArchive, archiveFile.Name)
		}
		// 条目名称必须通过目录穿越检查。
		if !safeArchivePath(archiveFile.Name) {
			return fmt.Errorf("%w: path=%s", ErrUnsafeArchive, archiveFile.Name)
		}
		// 先根据条目名称提取小写扩展名。
		extension := strings.ToLower(filepath.Ext(archiveFile.Name))
		// 未允许嵌套归档时拒绝常见归档扩展名。
		if !policy.allowNestedArchives && containsString(nestedArchiveExtensions, extension) {
			return fmt.Errorf("%w: nested archive=%s", ErrUnsafeArchive, archiveFile.Name)
		}
		// 累加声明大小前检查无符号整数溢出。
		if archiveFile.UncompressedSize64 > math.MaxUint64-expandedBytes {
			return fmt.Errorf("%w: expanded size overflow", ErrUnsafeArchive)
		}
		// 累加当前条目的声明解压大小。
		expandedBytes += archiveFile.UncompressedSize64
		// 声明解压总量超过策略时立即拒绝。
		if expandedBytes > uint64(policy.maxArchiveExpandedBytes) {
			return fmt.Errorf("%w: expanded=%d max=%d", ErrUnsafeArchive, expandedBytes, policy.maxArchiveExpandedBytes)
		}
		// 空压缩体按一个字节计算，避免压缩比除零。
		compressedSize := archiveFile.CompressedSize64
		if compressedSize == 0 {
			compressedSize = 1
		}
		// 使用条目声明大小计算压缩比。
		ratio := float64(archiveFile.UncompressedSize64) / float64(compressedSize)
		// 压缩比超过策略时按压缩炸弹风险拒绝。
		if ratio > policy.maxCompressionRatio {
			return fmt.Errorf("%w: entry=%s ratio=%.2f max=%.2f", ErrUnsafeArchive, archiveFile.Name, ratio, policy.maxCompressionRatio)
		}
		// 目录条目没有内容，不执行实际解压检查。
		if archiveFile.FileInfo().IsDir() {
			continue
		}
		// 打开当前条目的解压数据流。
		entry, openErr := archiveFile.Open()
		// 条目无法打开时归档结构不可信。
		if openErr != nil {
			return fmt.Errorf("%w: open entry=%s: %v", ErrUnsafeArchive, archiveFile.Name, openErr)
		}
		// 计算当前归档仍可读取的安全字节数。
		remainingBytes := policy.maxArchiveExpandedBytes - actualExpandedBytes
		// 默认读取到剩余上限，用于识别真实解压大小。
		readLimit := remainingBytes
		// 多读取一个字节，用于准确判断是否超过上限。
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		// 为当前条目设置实际解压读取上限。
		limitedEntry := &io.LimitedReader{R: entry, N: readLimit}
		// 内容识别只探测固定上限内的条目前缀。
		probeSize := min(int64(archiveEntryProbeSize), readLimit)
		// 分配当前条目的 MIME 探测缓冲区。
		probe := make([]byte, probeSize)
		// 尽量读取完整探测区，短条目允许提前结束。
		probeBytes, probeErr := io.ReadFull(limitedEntry, probe)
		// EOF 和短读取属于正常条目结束，其他错误直接拒绝。
		if probeErr != nil && !errors.Is(probeErr, io.EOF) && !errors.Is(probeErr, io.ErrUnexpectedEOF) {
			_ = entry.Close()
			return fmt.Errorf("%w: inspect entry=%s: %v", ErrUnsafeArchive, archiveFile.Name, probeErr)
		}
		// 读取到内容后根据真实字节识别条目类型。
		if probeBytes > 0 {
			// 识别条目前缀的真实 MIME 类型。
			entryMIME := normalizeMIMEType(mimetype.Detect(probe[:probeBytes]).String())
			// 防止仅修改扩展名绕过嵌套归档和 ZIP 容器限制。
			if !policy.allowNestedArchives && (isArchiveMIME(entryMIME) || isZIPContainerMIME(entryMIME)) {
				_ = entry.Close()
				return fmt.Errorf("%w: nested archive content=%s", ErrUnsafeArchive, archiveFile.Name)
			}
		}
		// 从缓冲池获取剩余条目内容的复制缓冲区。
		bufferPointer := copyBufferPool.Get().(*[]byte)
		// 读取并丢弃剩余解压内容，只统计真实字节数。
		copiedBytes, copyErr := copyWithContext(ctx, io.Discard, limitedEntry, *bufferPointer)
		// 当前条目读取完成后立即归还共享缓冲区。
		copyBufferPool.Put(bufferPointer)
		// 主动关闭条目读取流并保存关闭结果。
		closeErr := entry.Close()
		// 解压读取或关闭失败都表示归档不可完整验证。
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("%w: read entry=%s: %v", ErrUnsafeArchive, archiveFile.Name, errors.Join(copyErr, closeErr))
		}
		// 累加探测区和剩余内容的真实解压字节数。
		actualExpandedBytes += int64(probeBytes) + copiedBytes
		// 真实解压总量超过策略时拒绝归档。
		if actualExpandedBytes > policy.maxArchiveExpandedBytes {
			return fmt.Errorf("%w: actual expanded=%d max=%d", ErrUnsafeArchive, actualExpandedBytes, policy.maxArchiveExpandedBytes)
		}
	}
	// 所有条目检查完成后恢复隔离文件偏移。
	return staged.seekStart()
}

// safeArchivePath 检查归档条目不会目录穿越。
// @param fileName string 归档条目名称
// @return result bool 是否安全
func safeArchivePath(fileName string) bool {
	// 统一归档条目的路径分隔符。
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	// 空名称、绝对路径、盘符、数据流和空字符都不允许进入归档。
	if fileName == "" || strings.HasPrefix(fileName, "/") || strings.Contains(fileName, ":") || strings.ContainsRune(fileName, '\x00') {
		return false
	}
	// 目录条目允许一个末尾分隔符，其余路径必须保持原样。
	normalized := strings.TrimSuffix(fileName, "/")
	if normalized == "" {
		return false
	}
	// 折叠当前目录和重复分隔符后检查父目录穿越。
	cleaned := path.Clean(normalized)
	// 允许规范相对路径，拒绝父目录、隐藏目录段和静默路径改写。
	return cleaned == normalized && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

// containsString 判断字符串切片是否包含目标值。
// @param values []string 字符串列表
// @param target string 目标值
// @return result bool 是否包含
func containsString(values []string, target string) bool {
	// 顺序扫描短列表，避免为静态小集合创建映射。
	for _, value := range values {
		// 找到完全相同的字符串后立即返回。
		if value == target {
			return true
		}
	}
	// 完成扫描后仍未找到目标值。
	return false
}
