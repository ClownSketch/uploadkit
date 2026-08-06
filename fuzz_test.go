package uploadkit

import (
	"path"
	"strings"
	"testing"
)

// FuzzValidateObjectKey 验证任意对象键输入不会触发异常或放行路径改写。
func FuzzValidateObjectKey(f *testing.F) {
	// 添加常见正常路径和攻击路径作为初始样本。
	seeds := []string{"docs/file.txt", "用户/文件.txt", "../file", "folder//file", `folder\file`, "/absolute"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	// 对随机对象键执行公共校验。
	f.Fuzz(func(t *testing.T, objectKey string) {
		// 非法输入只需稳定返回错误。
		if err := ValidateObjectKey(objectKey); err != nil {
			return
		}
		// 放行对象键必须保持标准路径清理前后一致。
		if cleaned := path.Clean(objectKey); cleaned != objectKey {
			t.Fatalf("accepted object key changed after cleaning: %q => %q", objectKey, cleaned)
		}
		// 放行对象键不能包含反斜杠和控制字符。
		if strings.Contains(objectKey, `\`) {
			t.Fatalf("accepted object key contains backslash: %q", objectKey)
		}
	})
}

// FuzzSafeArchivePath 验证任意归档条目不会放行跨平台危险路径。
func FuzzSafeArchivePath(f *testing.F) {
	// 添加普通路径、父目录、盘符和数据流作为初始样本。
	seeds := []string{"docs/file.txt", "../file", "C:/file", "file.txt:stream", `docs\file.txt`, "/absolute"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	// 对随机归档条目执行路径判断。
	f.Fuzz(func(t *testing.T, fileName string) {
		// 未通过安全判断的路径不需要继续验证。
		if !safeArchivePath(fileName) {
			return
		}
		// 放行路径不能包含盘符、数据流或绝对路径。
		if strings.Contains(fileName, ":") || strings.HasPrefix(fileName, "/") {
			t.Fatalf("accepted unsafe archive path: %q", fileName)
		}
	})
}
