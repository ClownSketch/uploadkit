package uploadkit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

const (
	randomKeyBytes   = 16   // randomKeyBytes 生成 128 位随机对象名称
	maxObjectKeySize = 1024 // maxObjectKeySize 通用云存储对象键长度上限
)

// DefaultKeyGenerator 使用日期、随机值和可信 MIME 扩展名创建对象键。
// @param input KeyInput 对象键信息
// @return objectKey string 对象键
// @return err error 随机数或前缀错误
func DefaultKeyGenerator(input KeyInput) (objectKey string, err error) {
	// 先校验目录前缀，禁止对象键越过调用方允许的目录。
	prefix, err := cleanObjectPrefix(input.Prefix)
	// 前缀非法时不生成任何随机数据。
	if err != nil {
		return "", err
	}
	// 分配固定长度随机字节，生成不可预测的对象名称。
	randomBytes := make([]byte, randomKeyBytes)
	// 使用密码学安全随机源填充对象名称。
	if _, err = rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate upload object key: %w", err)
	}
	// 扩展名只根据真实 MIME 选择，不使用客户端文件名。
	fileName := hex.EncodeToString(randomBytes) + safeExtension(input.MIMEType)
	// 使用 UTC 日期目录控制单目录对象数量。
	return path.Join(prefix, input.CreatedAt.UTC().Format("2006/01/02"), fileName), nil
}

// cleanObjectPrefix 校验调用方目录前缀不能越过对象根目录。
// @param prefix string 调用方目录前缀
// @return result string 规范前缀
// @return err error 非法路径错误
func cleanObjectPrefix(prefix string) (result string, err error) {
	// 清除目录两端空白，避免空白成为对象命名的一部分。
	prefix = strings.TrimSpace(prefix)
	// 空前缀表示直接使用默认日期目录。
	if prefix == "" {
		return "", nil
	}
	// 拒绝绝对路径、反斜杠和包含空字符的目录。
	if strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "\\") || strings.ContainsRune(prefix, '\x00') {
		return "", ErrInvalidObjectKey
	}
	// 目录前缀允许携带一个或多个末尾分隔符。
	prefix = strings.TrimRight(prefix, "/")
	// 清除末尾分隔符后为空的目录仍属于非法绝对路径。
	if prefix == "" {
		return "", ErrInvalidObjectKey
	}
	// 使用标准路径规则检查重复分隔符和隐藏目录段。
	cleaned := path.Clean(prefix)
	// 非规范路径必须直接拒绝，不能静默改变调用方的对象命名空间。
	if cleaned != prefix || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrInvalidObjectKey
	}
	// 返回已经确认规范的对象目录。
	return cleaned, nil
}

// ValidateObjectKey 校验适配器收到的对象键。
// @param objectKey string 对象键
// @return err error 非法对象键
func ValidateObjectKey(objectKey string) error {
	// 拒绝空值、隐式空白、超长键、反斜杠和绝对路径。
	if objectKey == "" || objectKey != strings.TrimSpace(objectKey) || len(objectKey) > maxObjectKeySize ||
		strings.Contains(objectKey, "\\") || strings.HasPrefix(objectKey, "/") {
		return ErrInvalidObjectKey
	}
	// 逐字符拒绝控制字符，避免协议头和日志内容被注入。
	for _, character := range objectKey {
		// ASCII 控制区和删除字符都不允许进入对象键。
		if character < 0x20 || character == 0x7f {
			return ErrInvalidObjectKey
		}
	}
	// 标准化后必须与原值完全一致，防止隐藏路径段。
	cleaned := path.Clean(objectKey)
	// 拒绝当前目录、父目录、目录穿越和可被折叠的对象键。
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != objectKey {
		return ErrInvalidObjectKey
	}
	// 对象键通过全部结构校验。
	return nil
}
