package uploadkit

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"mime"
	"strings"
	"time"
)

// PutObject 描述一个已经通过检查、等待持久化的对象。
type PutObject struct {
	Key                string            // Key 对象存储键
	Body               io.ReadSeeker     // Body 可回退的隔离文件流
	Size               int64             // Size 实际文件字节数
	ContentType        string            // ContentType 真实 MIME 类型
	ContentDisposition string            // ContentDisposition 下载展示方式
	ChecksumSHA256     string            // ChecksumSHA256 十六进制 SHA-256
	Metadata           map[string]string // Metadata 调用方提供的对象元数据副本
}

// StoredObject 描述 Store 返回的持久化结果。
type StoredObject struct {
	ETag      string // ETag 存储服务返回的对象标识
	VersionID string // VersionID 开启版本控制时的对象版本
}

// Store 定义本地和云对象存储统一适配接口。
type Store interface {
	// Put 保存已经通过检查的对象。
	Put(ctx context.Context, object PutObject) (StoredObject, error)
	// Delete 删除指定对象；对象不存在应视为成功。
	Delete(ctx context.Context, objectKey string) error
}

// URLSigner 是支持临时签名访问地址的可选存储能力。
type URLSigner interface {
	// SignedURL 为指定对象创建临时访问地址。
	SignedURL(ctx context.Context, objectKey string, expires time.Duration) (string, error)
}

// HealthChecker 是支持主动连接检查的可选存储能力。
type HealthChecker interface {
	// Ping 验证凭证、端点和 Bucket 是否可访问。
	Ping(ctx context.Context) error
}

// ValidatePutObject 校验对象存储适配器收到的完整写入参数。
// @param object PutObject 待保存对象
// @return err error 对象键、内容事实或元数据错误
func ValidatePutObject(object PutObject) error {
	// 对象键必须符合所有存储适配器共享的结构规则。
	if err := ValidateObjectKey(object.Key); err != nil {
		return err
	}
	// 对象内容必须提供可回退读取流。
	if object.Body == nil {
		return ErrNilSource
	}
	// 上传流程不接受空文件。
	if object.Size == 0 {
		return ErrEmptyFile
	}
	// 负数不是有效的已确认对象大小。
	if object.Size < 0 {
		return fmt.Errorf("%w: object size is invalid", ErrInvalidConfig)
	}
	// 存储层必须收到已识别的标准 MIME 类型。
	contentType := normalizeMIMEType(object.ContentType)
	contentTypeParts := strings.Split(contentType, "/")
	if len(contentTypeParts) != 2 || contentTypeParts[0] == "" || contentTypeParts[1] == "" ||
		strings.Contains(contentType, "*") || contentType != object.ContentType {
		return fmt.Errorf("%w: object content type is invalid", ErrInvalidConfig)
	}
	// 使用标准解析器拒绝畸形 MIME 类型。
	if _, _, err := mime.ParseMediaType(contentType); err != nil {
		return fmt.Errorf("%w: object content type is invalid", ErrInvalidConfig)
	}
	// SHA-256 必须是完整的六十四位十六进制字符串。
	checksum, err := hex.DecodeString(object.ChecksumSHA256)
	if err != nil || len(checksum) != 32 {
		return fmt.Errorf("%w: object checksum is invalid", ErrInvalidConfig)
	}
	// 展示方式不能包含响应头注入字符。
	disposition, err := normalizeContentDisposition(object.ContentDisposition)
	if err != nil {
		return err
	}
	// 适配器只接收已经完成默认值处理的展示方式。
	if disposition != object.ContentDisposition {
		return fmt.Errorf("%w: object content disposition is not normalized", ErrInvalidConfig)
	}
	// 元数据必须符合跨存储服务的公共安全规则。
	metadata, err := normalizeMetadata(object.Metadata)
	if err != nil {
		return err
	}
	// 适配器只接收已经规范为小写安全键的元数据。
	if !maps.Equal(metadata, object.Metadata) {
		return fmt.Errorf("%w: object metadata is not normalized", ErrInvalidConfig)
	}
	// 对象写入参数通过全部公共校验。
	return nil
}
