package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ClownSketch/uploadkit"
)

const (
	ruleKindSHA256 = "sha256" // ruleKindSHA256 已知文件摘要精确命中
	ruleKindBytes  = "bytes"  // ruleKindBytes 适用格式内的字节特征匹配
	maxRuleIDLen   = 128      // maxRuleIDLen 规则 ID 长度上限
	maxThreatLen   = 256      // maxThreatLen 威胁名称长度上限
	maxMIMERules   = 32       // maxMIMERules 单条规则适用 MIME 数量上限
	// MaxRulePackBytes 是规则包原始字节上限（1 MiB）。
	// 它约束加载阶段的内存占用，先于摘要校验与 JSON 解析生效；
	// 与单次上传内容扫描的 MaxScanBytes 相互独立。
	// 取值依据：规则包是已审核的本地配置，不是上传载荷；1 MiB 足够容纳
	// 大量摘要规则和有限长度特征，同时避免异常或被替换的超大文件在验签前占满内存。
	MaxRulePackBytes = 1 << 20
)

// RulePack 描述一次上传可使用的不可变规则版本。
type RulePack struct {
	Version      string `json:"version"`        // Version 规则包版本，必须稳定可追溯
	MaxScanBytes int64  `json:"max_scan_bytes"` // MaxScanBytes 单次扫描可读字节上限，零值使用引擎默认
	Rules        []Rule `json:"rules"`          // Rules 已审核规则列表
}

// Rule 描述一条可测试、可追溯的离线检测规则。
type Rule struct {
	ID      string   `json:"id"`      // ID 稳定规则标识
	Kind    string   `json:"kind"`    // Kind 规则类型，支持 sha256 与 bytes
	SHA256  string   `json:"sha256"`  // SHA256 完整文件摘要，仅 kind=sha256 使用
	Pattern string   `json:"pattern"` // Pattern 十六进制字节特征，仅 kind=bytes 使用
	MIME    []string `json:"mime"`    // MIME 适用真实类型，空表示全部已支持格式
	Threat  string   `json:"threat"`  // Threat 命中后返回的威胁名称
}

// compiledRule 保存完成校验并编译后的只读规则。
type compiledRule struct {
	id        string              // id 稳定规则标识
	kind      string              // kind 规则类型
	sha256    string              // sha256 规范化摘要
	pattern   []byte              // pattern 编译后的字节特征
	mimeExact map[string]struct{} // mimeExact 精确 MIME 集合
	mimeAll   bool                // mimeAll 是否适用于全部类型
	threat    string              // threat 威胁名称
}

// LoadRulePackFile 从本地可信路径加载规则包并校验完整性。
// @param path string 规则包文件路径
// @param expectedSHA256 string 规则包原始字节的十六进制 SHA-256
// @return pack RulePack 规则包
// @return digest string 实际摘要
// @return err error 读取、完整性或结构错误
func LoadRulePackFile(path string, expectedSHA256 string) (pack RulePack, digest string, err error) {
	// 规则包路径不能为空。
	path = strings.TrimSpace(path)
	if path == "" {
		return RulePack{}, "", fmt.Errorf("%w: offline rule pack path is empty", uploadkit.ErrInvalidConfig)
	}
	// 打开本地规则包；运行时不联网获取规则。
	file, err := os.Open(path)
	if err != nil {
		return RulePack{}, "", fmt.Errorf("%w: open offline rule pack: %v", uploadkit.ErrInvalidConfig, err)
	}
	// 读取结束后关闭文件句柄。
	defer file.Close()
	// 最多读取上限加一字节，用于判断超限；不先读完整包，也不只依赖文件大小预检。
	raw, err := io.ReadAll(io.LimitReader(file, int64(MaxRulePackBytes)+1))
	if err != nil {
		return RulePack{}, "", fmt.Errorf("%w: read offline rule pack: %v", uploadkit.ErrInvalidConfig, err)
	}
	// 复用字节加载入口完成长度、摘要与结构校验。
	return LoadRulePackBytes(raw, expectedSHA256)
}

// LoadRulePackBytes 解析规则包原始字节并校验完整性。
// @param raw []byte 规则包原始内容
// @param expectedSHA256 string 期望的十六进制 SHA-256
// @return pack RulePack 规则包
// @return digest string 实际摘要
// @return err error 完整性或结构错误
func LoadRulePackBytes(raw []byte, expectedSHA256 string) (pack RulePack, digest string, err error) {
	// 空规则包不能作为健康引擎启动。
	if len(raw) == 0 {
		return RulePack{}, "", fmt.Errorf("%w: offline rule pack is empty", uploadkit.ErrInvalidConfig)
	}
	// 先限制原始字节长度，再计算摘要和解析 JSON，避免超大包占用内存。
	if len(raw) > MaxRulePackBytes {
		return RulePack{}, "", fmt.Errorf("%w: offline rule pack exceeds max size bytes=%d max=%d", uploadkit.ErrInvalidConfig, len(raw), MaxRulePackBytes)
	}
	// 计算规则包原始字节摘要，供完整性核对与审计记录。
	sum := sha256.Sum256(raw)
	digest = hex.EncodeToString(sum[:])
	// 生产装配必须提供期望摘要，防止静默加载被篡改文件。
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expected == "" {
		return RulePack{}, "", fmt.Errorf("%w: offline rule pack digest is required", uploadkit.ErrInvalidConfig)
	}
	// 摘要不匹配时拒绝加载，调用方应回滚到上一可信版本。
	if digest != expected {
		return RulePack{}, digest, fmt.Errorf("%w: offline rule pack digest mismatch", uploadkit.ErrInvalidConfig)
	}
	// 解析 JSON 规则包结构。
	if err = json.Unmarshal(raw, &pack); err != nil {
		return RulePack{}, digest, fmt.Errorf("%w: offline rule pack is corrupt: %v", uploadkit.ErrInvalidConfig, err)
	}
	// 返回通过完整性校验的规则包。
	return pack, digest, nil
}

// compileRulePack 校验规则合法性并编译为只读匹配结构。
// @param pack RulePack 规则包
// @param limits engineLimits 资源上限
// @return rules []compiledRule 编译规则
// @return maxScanBytes int64 扫描字节上限
// @return err error 合法性错误
func compileRulePack(pack RulePack, limits engineLimits) (rules []compiledRule, maxScanBytes int64, err error) {
	// 版本号是规则可追溯性的必需字段。
	version := strings.TrimSpace(pack.Version)
	if version == "" {
		return nil, 0, fmt.Errorf("%w: offline rule pack version is empty", uploadkit.ErrInvalidConfig)
	}
	// 空规则集不能冒充健康防护能力。
	if len(pack.Rules) == 0 {
		return nil, 0, fmt.Errorf("%w: offline rule pack contains no rules", uploadkit.ErrInvalidConfig)
	}
	// 规则数量超过引擎上限时拒绝启动。
	if len(pack.Rules) > limits.maxRules {
		return nil, 0, fmt.Errorf("%w: offline rule count exceeds limit", uploadkit.ErrInvalidConfig)
	}
	// 扫描字节上限优先使用规则包声明，零值回退引擎默认。
	maxScanBytes = pack.MaxScanBytes
	if maxScanBytes == 0 {
		maxScanBytes = limits.maxScanBytes
	}
	// 扫描上限必须为正且不超过引擎硬上限。
	if maxScanBytes < 1 || maxScanBytes > limits.maxScanBytes {
		return nil, 0, fmt.Errorf("%w: offline max scan bytes is invalid", uploadkit.ErrInvalidConfig)
	}
	// 预分配编译结果并记录已出现的规则 ID。
	rules = make([]compiledRule, 0, len(pack.Rules))
	seenIDs := make(map[string]struct{}, len(pack.Rules))
	// 逐条校验并编译规则。
	for _, rule := range pack.Rules {
		compiled, compileErr := compileRule(rule, limits)
		if compileErr != nil {
			return nil, 0, compileErr
		}
		// 规则 ID 必须在同一版本内唯一。
		if _, exists := seenIDs[compiled.id]; exists {
			return nil, 0, fmt.Errorf("%w: duplicate offline rule id=%s", uploadkit.ErrInvalidConfig, compiled.id)
		}
		seenIDs[compiled.id] = struct{}{}
		rules = append(rules, compiled)
	}
	// 返回不可变规则版本使用的编译结果。
	return rules, maxScanBytes, nil
}

// compileRule 校验并编译单条规则。
// @param rule Rule 原始规则
// @param limits engineLimits 资源上限
// @return result compiledRule 编译规则
// @return err error 合法性错误
func compileRule(rule Rule, limits engineLimits) (result compiledRule, err error) {
	// 规范并校验稳定规则 ID。
	id := strings.TrimSpace(rule.ID)
	if id == "" || len(id) > maxRuleIDLen {
		return compiledRule{}, fmt.Errorf("%w: offline rule id is invalid", uploadkit.ErrInvalidConfig)
	}
	// 威胁名称是命中结论的必需字段。
	threat := strings.TrimSpace(rule.Threat)
	if threat == "" || len(threat) > maxThreatLen {
		return compiledRule{}, fmt.Errorf("%w: offline rule threat is invalid id=%s", uploadkit.ErrInvalidConfig, id)
	}
	// 规范规则类型。
	kind := strings.ToLower(strings.TrimSpace(rule.Kind))
	// 编译适用 MIME 范围。
	mimeExact, mimeAll, err := compileRuleMIME(rule.MIME)
	if err != nil {
		return compiledRule{}, fmt.Errorf("%w: offline rule mime is invalid id=%s: %v", uploadkit.ErrInvalidConfig, id, err)
	}
	// 按类型分别校验特征载荷。
	switch kind {
	case ruleKindSHA256:
		// SHA-256 规则不能携带字节特征。
		if strings.TrimSpace(rule.Pattern) != "" {
			return compiledRule{}, fmt.Errorf("%w: sha256 rule cannot include pattern id=%s", uploadkit.ErrInvalidConfig, id)
		}
		// 摘要必须是 64 位十六进制。
		digest := strings.ToLower(strings.TrimSpace(rule.SHA256))
		if len(digest) != sha256.Size*2 || !isHexString(digest) {
			return compiledRule{}, fmt.Errorf("%w: sha256 rule digest is invalid id=%s", uploadkit.ErrInvalidConfig, id)
		}
		return compiledRule{id: id, kind: kind, sha256: digest, mimeExact: mimeExact, mimeAll: mimeAll, threat: threat}, nil
	case ruleKindBytes:
		// 字节特征规则不能携带文件摘要。
		if strings.TrimSpace(rule.SHA256) != "" {
			return compiledRule{}, fmt.Errorf("%w: bytes rule cannot include sha256 id=%s", uploadkit.ErrInvalidConfig, id)
		}
		// 特征使用十六进制编码，避免 JSON 中的不可打印字符歧义。
		pattern, decodeErr := hex.DecodeString(strings.TrimSpace(rule.Pattern))
		if decodeErr != nil || len(pattern) == 0 {
			return compiledRule{}, fmt.Errorf("%w: bytes rule pattern is invalid id=%s", uploadkit.ErrInvalidConfig, id)
		}
		// 特征长度必须受引擎上限约束。
		if len(pattern) > limits.maxPatternLength {
			return compiledRule{}, fmt.Errorf("%w: bytes rule pattern exceeds limit id=%s", uploadkit.ErrInvalidConfig, id)
		}
		return compiledRule{id: id, kind: kind, pattern: pattern, mimeExact: mimeExact, mimeAll: mimeAll, threat: threat}, nil
	default:
		return compiledRule{}, fmt.Errorf("%w: unsupported offline rule kind=%s id=%s", uploadkit.ErrInvalidConfig, kind, id)
	}
}

// compileRuleMIME 编译规则适用的真实 MIME 范围。
// @param values []string MIME 列表
// @return exact map[string]struct{} 精确类型
// @return all bool 是否匹配全部类型
// @return err error 非法 MIME 错误
func compileRuleMIME(values []string) (exact map[string]struct{}, all bool, err error) {
	// 未声明 MIME 时对引擎支持的全部输入生效。
	if len(values) == 0 {
		return nil, true, nil
	}
	// 限制单条规则的 MIME 数量。
	if len(values) > maxMIMERules {
		return nil, false, fmt.Errorf("too many mime rules")
	}
	exact = make(map[string]struct{}, len(values))
	for _, value := range values {
		mimeType := strings.ToLower(strings.TrimSpace(value))
		if mimeType == "" {
			return nil, false, fmt.Errorf("empty mime")
		}
		// */* 显式表示全部类型。
		if mimeType == "*/*" {
			all = true
			continue
		}
		if strings.Count(mimeType, "/") != 1 || strings.Contains(mimeType, "*") {
			return nil, false, fmt.Errorf("invalid mime=%s", mimeType)
		}
		exact[mimeType] = struct{}{}
	}
	if all {
		return nil, true, nil
	}
	return exact, false, nil
}

// matchesMIME 判断文件真实类型是否落入规则适用范围。
// @param mimeType string 真实 MIME
// @return matched bool 是否适用
func (r compiledRule) matchesMIME(mimeType string) bool {
	if r.mimeAll {
		return true
	}
	_, matched := r.mimeExact[strings.ToLower(strings.TrimSpace(mimeType))]
	return matched
}

// isHexString 判断字符串是否全部为十六进制字符。
// @param value string 待检查字符串
// @return result bool 是否为十六进制
func isHexString(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
