// Package offline 提供进程内、离线、同步的自研内容扫描器。
//
// 通过只表示：在当前不可变规则版本、支持格式以及检查字节范围内未发现命中。
// 测试规则包只能证明扫描链路可执行，不能证明具备生产恶意软件检出能力。
package offline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ClownSketch/uploadkit"
)

const (
	defaultMaxScanBytes     = 10 << 20 // defaultMaxScanBytes 默认单次扫描字节上限
	defaultMaxRules         = 4096     // defaultMaxRules 默认规则数量上限
	defaultMaxPatternLength = 4096     // defaultMaxPatternLength 默认特征长度上限
	scanChunkSize           = 64 << 10 // scanChunkSize 流式扫描分块大小
)

// engineLimits 保存引擎硬性资源上限。
type engineLimits struct {
	maxScanBytes     int64 // maxScanBytes 单次扫描字节硬上限
	maxRules         int   // maxRules 规则数量硬上限
	maxPatternLength int   // maxPatternLength 特征长度硬上限
}

// Config 定义离线扫描器装配参数。
type Config struct {
	RulePack         RulePack // RulePack 已通过完整性校验的规则包
	RulePackDigest   string   // RulePackDigest 规则包摘要，仅用于审计记录
	MaxScanBytes     int64    // MaxScanBytes 引擎硬上限，零值使用默认
	MaxRules         int      // MaxRules 规则数量硬上限，零值使用默认
	MaxPatternLength int      // MaxPatternLength 特征长度硬上限，零值使用默认
}

// Scanner 使用本地不可变规则版本同步扫描上传内容。
type Scanner struct {
	version      string         // version 当前规则版本
	digest       string         // digest 规则包摘要
	maxScanBytes int64          // maxScanBytes 单次扫描可读上限
	hashRules    []compiledRule // hashRules SHA-256 精确命中规则
	byteRules    []compiledRule // byteRules 字节特征规则
	maxPattern   int            // maxPattern 最长特征长度，用于跨块重叠
}

// New 创建离线扫描器。
// @param config Config 扫描器配置
// @return result *Scanner 扫描器
// @return err error 配置或规则错误
func New(config Config) (result *Scanner, err error) {
	// 组装引擎资源上限，零值回退安全默认。
	limits := engineLimits{
		maxScanBytes:     config.MaxScanBytes,
		maxRules:         config.MaxRules,
		maxPatternLength: config.MaxPatternLength,
	}
	if limits.maxScanBytes == 0 {
		limits.maxScanBytes = defaultMaxScanBytes
	}
	if limits.maxRules == 0 {
		limits.maxRules = defaultMaxRules
	}
	if limits.maxPatternLength == 0 {
		limits.maxPatternLength = defaultMaxPatternLength
	}
	// 资源上限必须为正数。
	if limits.maxScanBytes < 1 || limits.maxRules < 1 || limits.maxPatternLength < 1 {
		return nil, fmt.Errorf("%w: offline scanner limits are invalid", uploadkit.ErrInvalidConfig)
	}
	// 编译规则包；空包、损坏字段或不合法规则都会导致初始化失败。
	rules, maxScanBytes, err := compileRulePack(config.RulePack, limits)
	if err != nil {
		return nil, err
	}
	// 分类保存哈希规则与字节特征规则。
	hashRules := make([]compiledRule, 0)
	byteRules := make([]compiledRule, 0)
	maxPattern := 0
	for _, rule := range rules {
		switch rule.kind {
		case ruleKindSHA256:
			hashRules = append(hashRules, rule)
		case ruleKindBytes:
			byteRules = append(byteRules, rule)
			if len(rule.pattern) > maxPattern {
				maxPattern = len(rule.pattern)
			}
		}
	}
	// 保存不可变规则版本，一次上传只使用该版本。
	return &Scanner{
		version:      strings.TrimSpace(config.RulePack.Version),
		digest:       strings.ToLower(strings.TrimSpace(config.RulePackDigest)),
		maxScanBytes: maxScanBytes,
		hashRules:    hashRules,
		byteRules:    byteRules,
		maxPattern:   maxPattern,
	}, nil
}

// NewFromFile 从本地规则包文件创建离线扫描器。
// @param path string 规则包路径
// @param expectedSHA256 string 规则包期望摘要
// @return result *Scanner 扫描器
// @return err error 读取、完整性或配置错误
func NewFromFile(path string, expectedSHA256 string) (result *Scanner, err error) {
	// 先加载并校验规则包完整性。
	pack, digest, err := LoadRulePackFile(path, expectedSHA256)
	if err != nil {
		return nil, err
	}
	// 使用已校验规则包装配引擎。
	return New(Config{RulePack: pack, RulePackDigest: digest})
}

// Version 返回当前不可变规则版本。
// @return result string 规则版本
func (s *Scanner) Version() string {
	if s == nil {
		return ""
	}
	return s.version
}

// Digest 返回当前规则包摘要。
// @return result string 规则包 SHA-256
func (s *Scanner) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

// Scan 使用当前规则版本同步检查文件内容。
// @param ctx context.Context 调用上下文
// @param file uploadkit.FileInfo 文件信息
// @param content io.Reader 从起点开始的文件内容
// @return result uploadkit.ScanResult 扫描结论
// @return err error 扫描未完成错误
func (s *Scanner) Scan(ctx context.Context, file uploadkit.FileInfo, content io.Reader) (result uploadkit.ScanResult, err error) {
	// 扫描器必须完成初始化后才能使用。
	if s == nil {
		return uploadkit.ScanResult{}, fmt.Errorf("%w: offline scanner is nil", uploadkit.ErrScanIncomplete)
	}
	// 内容读取器是扫描的必需输入。
	if content == nil {
		return uploadkit.ScanResult{}, fmt.Errorf("%w: offline scanner content is nil", uploadkit.ErrScanIncomplete)
	}
	// 先响应调用方取消信号。
	if err = ctx.Err(); err != nil {
		return uploadkit.ScanResult{}, err
	}
	// 文件大小超过扫描能力时返回未完成，不能伪装成未命中。
	if file.Size < 0 || file.Size > s.maxScanBytes {
		return uploadkit.ScanResult{}, fmt.Errorf("%w: file exceeds offline scan capacity size=%d max=%d", uploadkit.ErrScanIncomplete, file.Size, s.maxScanBytes)
	}
	// 按真实 MIME 收集适用的摘要规则与字节规则；无 MIME 限制的规则适用于全部类型。
	hashRules := s.applicableRules(s.hashRules, file.MIMEType)
	byteRules := s.applicableRules(s.byteRules, file.MIMEType)
	// 没有任何适用规则时属于“无法检查”，不能伪装成检查后未命中。
	if len(hashRules) == 0 && len(byteRules) == 0 {
		return uploadkit.ScanResult{}, fmt.Errorf("%w: no applicable offline rules for mime=%s", uploadkit.ErrScanIncomplete, file.MIMEType)
	}
	// 优先执行适用的摘要精确命中，避免不必要的流式读取。
	if threat := matchHashRules(hashRules, file.ChecksumSHA256); threat != "" {
		return uploadkit.ScanResult{Clean: false, Threat: threat}, nil
	}
	// 仅有适用摘要规则且未命中时，表示已完成检查范围内的判定。
	if len(byteRules) == 0 {
		return uploadkit.ScanResult{Clean: true}, nil
	}
	// 流式匹配适用的字节特征，并处理分块边界与上下文取消。
	threat, err := s.matchByteRules(ctx, content, byteRules, file.Size)
	if err != nil {
		return uploadkit.ScanResult{}, err
	}
	if threat != "" {
		return uploadkit.ScanResult{Clean: false, Threat: threat}, nil
	}
	// 存在适用规则，检查全部完成且均未命中。
	return uploadkit.ScanResult{Clean: true}, nil
}

// applicableRules 过滤出适用于指定真实 MIME 的规则。
// @param rules []compiledRule 候选规则
// @param mimeType string 真实 MIME
// @return result []compiledRule 适用规则
func (s *Scanner) applicableRules(rules []compiledRule, mimeType string) []compiledRule {
	result := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		if rule.matchesMIME(mimeType) {
			result = append(result, rule)
		}
	}
	return result
}

// matchHashRules 在适用摘要规则中检查已知文件 SHA-256 精确命中。
// @param rules []compiledRule 适用摘要规则
// @param checksum string 文件 SHA-256
// @return threat string 命中威胁名称，未命中为空
func matchHashRules(rules []compiledRule, checksum string) string {
	digest := strings.ToLower(strings.TrimSpace(checksum))
	if digest == "" {
		return ""
	}
	for _, rule := range rules {
		if rule.sha256 == digest {
			return rule.threat
		}
	}
	return ""
}

// matchByteRules 分块扫描字节特征并保留跨块重叠窗口。
// @param ctx context.Context 调用上下文
// @param content io.Reader 文件内容
// @param rules []compiledRule 适用规则
// @param declaredSize int64 声明文件大小
// @return threat string 命中威胁名称
// @return err error 读取、超限或取消错误
func (s *Scanner) matchByteRules(ctx context.Context, content io.Reader, rules []compiledRule, declaredSize int64) (threat string, err error) {
	// overlap 保存上一分块末尾，用于跨边界匹配。
	var overlap []byte
	// readTotal 累加已读取字节，防止超过扫描能力。
	var readTotal int64
	// buffer 保存当前分块数据。
	buffer := make([]byte, scanChunkSize)
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		// 计算本轮仍允许读取的字节数。
		remaining := s.maxScanBytes - readTotal
		if remaining <= 0 {
			return "", fmt.Errorf("%w: offline scan byte limit exceeded", uploadkit.ErrScanIncomplete)
		}
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		n, readErr := content.Read(chunk)
		if n > 0 {
			readTotal += int64(n)
			// 拼接重叠窗口与当前分块，形成可匹配窗口。
			window := append(append([]byte{}, overlap...), chunk[:n]...)
			for _, rule := range rules {
				if bytes.Contains(window, rule.pattern) {
					return rule.threat, nil
				}
			}
			// 保留最长特征减一字节的重叠，覆盖跨块命中。
			overlapLen := s.maxPattern - 1
			if overlapLen < 0 {
				overlapLen = 0
			}
			if overlapLen > len(window) {
				overlapLen = len(window)
			}
			overlap = append([]byte{}, window[len(window)-overlapLen:]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				// 读取总量与隔离阶段确认大小不一致时视为扫描未完成。
				if declaredSize >= 0 && readTotal != declaredSize {
					return "", fmt.Errorf("%w: offline scan read size mismatch actual=%d declared=%d", uploadkit.ErrScanIncomplete, readTotal, declaredSize)
				}
				return "", nil
			}
			return "", fmt.Errorf("%w: %v", uploadkit.ErrScanIncomplete, readErr)
		}
	}
}
