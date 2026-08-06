// Package aliyunoss 实现阿里云 OSS 对象存储适配器。
package aliyunoss

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClownSketch/uploadkit"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

const checksumMetadataKey = "uploadkit-sha256" // checksumMetadataKey 文件哈希元数据键

// Config 定义阿里云 OSS 初始化参数。
type Config struct {
	Region          string       // Region Bucket 所在区域
	Bucket          string       // Bucket 存储桶名称
	Endpoint        string       // Endpoint 可选的自定义访问地址
	AccessKeyID     string       // AccessKeyID 访问密钥，可为空以使用默认凭证链
	AccessKeySecret string       // AccessKeySecret 访问密钥，可为空以使用默认凭证链
	SecurityToken   string       // SecurityToken 可选的临时凭证令牌
	UsePathStyle    bool         // UsePathStyle 是否使用路径式 Bucket 地址
	UseCName        bool         // UseCName Endpoint 是否为自定义域名
	AllowOverwrite  bool         // AllowOverwrite 是否允许覆盖同名对象
	MaxAttempts     int          // MaxAttempts SDK 最大请求尝试次数
	HTTPClient      *http.Client // HTTPClient 可选的自定义 HTTP 客户端
}

// clientAPI 定义适配器使用的阿里云 OSS 操作。
type clientAPI interface {
	PutObject(ctx context.Context, request *oss.PutObjectRequest, options ...func(*oss.Options)) (*oss.PutObjectResult, error)
	DeleteObject(ctx context.Context, request *oss.DeleteObjectRequest, options ...func(*oss.Options)) (*oss.DeleteObjectResult, error)
	GetBucketInfo(ctx context.Context, request *oss.GetBucketInfoRequest, options ...func(*oss.Options)) (*oss.GetBucketInfoResult, error)
	Presign(ctx context.Context, request any, options ...func(*oss.PresignOptions)) (*oss.PresignResult, error)
}

// Store 使用阿里云官方 SDK 保存对象。
type Store struct {
	client         clientAPI // client OSS 请求客户端
	bucket         string    // bucket 存储桶名称
	allowOverwrite bool      // allowOverwrite 是否允许覆盖同名对象
}

// New 创建阿里云 OSS 存储适配器。
// @param config Config 存储配置
// @return result *Store OSS 存储适配器
// @return err error 配置错误
func New(config Config) (result *Store, err error) {
	// 规范存储区域和 Bucket 名称。
	region := strings.TrimSpace(config.Region)
	bucket := strings.TrimSpace(config.Bucket)
	// 区域和 Bucket 是 OSS 请求的必需参数。
	if region == "" || bucket == "" {
		return nil, fmt.Errorf("%w: OSS region and bucket are required", uploadkit.ErrInvalidConfig)
	}
	// 清除静态凭证两端空白。
	accessKeyID := strings.TrimSpace(config.AccessKeyID)
	accessKeySecret := strings.TrimSpace(config.AccessKeySecret)
	// 静态凭证必须成对配置，否则使用 SDK 默认凭证链。
	if (accessKeyID == "") != (accessKeySecret == "") {
		return nil, fmt.Errorf("%w: OSS access key is incomplete", uploadkit.ErrInvalidConfig)
	}
	// 路径式和 CNAME 地址不能同时启用，重试次数不能为负数。
	if config.MaxAttempts < 0 || (config.UsePathStyle && config.UseCName) {
		return nil, fmt.Errorf("%w: OSS addressing or retry config is invalid", uploadkit.ErrInvalidConfig)
	}
	// 使用 SDK 默认配置并设置 Bucket 所在区域。
	sdkConfig := oss.LoadDefaultConfig().WithRegion(region)
	// 规范可选的 OSS 自定义端点。
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	// 自定义端点存在时校验协议和主机名。
	if endpoint != "" {
		parsedEndpoint, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" {
			return nil, fmt.Errorf("%w: invalid OSS endpoint", uploadkit.ErrInvalidConfig)
		}
		// 将经过校验的端点写入 SDK 配置。
		sdkConfig.WithEndpoint(endpoint)
	}
	// 配置静态凭证时覆盖 SDK 默认凭证链。
	if accessKeyID != "" {
		// 创建包含可选安全令牌的静态凭证提供器。
		provider := credentials.NewStaticCredentialsProvider(accessKeyID, accessKeySecret, strings.TrimSpace(config.SecurityToken))
		// 将凭证提供器写入 SDK 配置。
		sdkConfig.WithCredentialsProvider(provider)
	}
	// 调用方提供 HTTP Client 时复用其连接池和传输设置。
	if config.HTTPClient != nil {
		sdkConfig.WithHttpClient(config.HTTPClient)
	}
	// 正数请求次数覆盖 SDK 默认重试策略。
	if config.MaxAttempts > 0 {
		sdkConfig.WithRetryMaxAttempts(config.MaxAttempts)
	}
	// 配置路径式 Bucket 地址开关。
	sdkConfig.WithUsePathStyle(config.UsePathStyle)
	// 配置 CNAME 自定义域名开关。
	sdkConfig.WithUseCName(config.UseCName)
	// 创建并保存可并发复用的 OSS 客户端。
	return &Store{
		client:         oss.NewClient(sdkConfig),
		bucket:         bucket,
		allowOverwrite: config.AllowOverwrite,
	}, nil
}

// Put 保存已经通过 uploadkit 检查的对象。
// @param ctx context.Context 调用上下文
// @param object uploadkit.PutObject 待保存对象
// @return result uploadkit.StoredObject 存储结果
// @return err error SDK 写入错误
func (s *Store) Put(ctx context.Context, object uploadkit.PutObject) (result uploadkit.StoredObject, err error) {
	// 存储或 SDK 客户端为空时无法执行写入。
	if s == nil || s.client == nil {
		return uploadkit.StoredObject{}, uploadkit.ErrNilStore
	}
	// 写入操作统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.StoredObject{}, uploadkit.ErrNilContext
	}
	// 写入 SDK 前执行所有存储适配器共享的对象参数校验。
	if err = uploadkit.ValidatePutObject(object); err != nil {
		return uploadkit.StoredObject{}, err
	}
	// 官方适配器不依赖调用方当前游标，每次写入都从内容起点开始。
	if _, err = object.Body.Seek(0, io.SeekStart); err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("rewind OSS object body: %w", err)
	}
	// 复制调用方元数据，避免修改上层映射。
	metadata := make(map[string]string, len(object.Metadata)+1)
	for key, value := range object.Metadata {
		metadata[key] = value
	}
	// 写入核心层确认的 SHA-256，便于下载后校验。
	metadata[checksumMetadataKey] = object.ChecksumSHA256
	// 构建一次完整的 OSS PutObject 请求。
	request := &oss.PutObjectRequest{
		Bucket:             oss.Ptr(s.bucket),
		Key:                oss.Ptr(object.Key),
		Body:               object.Body,
		ContentLength:      oss.Ptr(object.Size),
		ContentType:        oss.Ptr(object.ContentType),
		ContentDisposition: oss.Ptr(object.ContentDisposition),
		Metadata:           metadata,
	}
	// 默认启用 OSS 原子禁止覆盖能力。
	if !s.allowOverwrite {
		request.ForbidOverwrite = oss.Ptr("true")
	}
	// 通过 SDK 写入对象并等待服务端结果。
	output, err := s.client.PutObject(ctx, request)
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		// 原子禁止覆盖被已存在对象拒绝时返回跨适配器统一错误。
		var serviceErr *oss.ServiceError
		if !s.allowOverwrite && errors.As(err, &serviceErr) &&
			(serviceErr.StatusCode == http.StatusConflict || serviceErr.StatusCode == http.StatusPreconditionFailed ||
				serviceErr.Code == "FileAlreadyExists" || serviceErr.Code == "PreconditionFailed") {
			return uploadkit.StoredObject{}, errors.Join(uploadkit.ErrObjectExists, fmt.Errorf("put OSS object: %w", err))
		}
		return uploadkit.StoredObject{}, fmt.Errorf("put OSS object: %w", err)
	}
	// 返回服务端对象标识和版本。
	return uploadkit.StoredObject{
		ETag:      strings.Trim(oss.ToString(output.ETag), "\""),
		VersionID: oss.ToString(output.VersionId),
	}, nil
}

// Delete 删除 OSS 对象；对象不存在由 OSS 视为成功。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @return err error SDK 删除错误
func (s *Store) Delete(ctx context.Context, objectKey string) error {
	// 存储或 SDK 客户端为空时无法执行删除。
	if s == nil || s.client == nil {
		return uploadkit.ErrNilStore
	}
	// 删除操作统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ErrNilContext
	}
	// 对象键进入 SDK 前再次执行公共结构校验。
	if err := uploadkit.ValidateObjectKey(objectKey); err != nil {
		return err
	}
	// 向当前 Bucket 提交删除请求。
	_, err := s.client.DeleteObject(ctx, &oss.DeleteObjectRequest{
		Bucket: oss.Ptr(s.bucket),
		Key:    oss.Ptr(objectKey),
	})
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		return fmt.Errorf("delete OSS object: %w", err)
	}
	// OSS 对不存在对象的删除保持幂等成功。
	return nil
}

// Ping 验证 OSS Bucket 和当前凭证可用。
// @param ctx context.Context 调用上下文
// @return err error SDK 检查错误
func (s *Store) Ping(ctx context.Context) error {
	// 存储或 SDK 客户端为空时无法执行检查。
	if s == nil || s.client == nil {
		return uploadkit.ErrNilStore
	}
	// 健康检查统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ErrNilContext
	}
	// 查询 Bucket 信息验证端点、凭证和访问权限。
	_, err := s.client.GetBucketInfo(ctx, &oss.GetBucketInfoRequest{Bucket: oss.Ptr(s.bucket)})
	// 检查失败时保留 SDK 错误链。
	if err != nil {
		return fmt.Errorf("check OSS bucket: %w", err)
	}
	// Bucket 当前可访问。
	return nil
}

// SignedURL 创建 OSS 临时下载地址。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @param expires time.Duration 有效时间
// @return result string 临时访问地址
// @return err error 参数或签名错误
func (s *Store) SignedURL(ctx context.Context, objectKey string, expires time.Duration) (result string, err error) {
	// 存储或 SDK 客户端为空时无法生成地址。
	if s == nil || s.client == nil {
		return "", uploadkit.ErrNilStore
	}
	// 签名操作统一要求调用方提供上下文。
	if ctx == nil {
		return "", uploadkit.ErrNilContext
	}
	// 对象键进入签名器前再次执行公共结构校验。
	if err = uploadkit.ValidateObjectKey(objectKey); err != nil {
		return "", err
	}
	// 有效期必须为正数。
	if expires <= 0 {
		return "", fmt.Errorf("%w: signed URL expiry is invalid", uploadkit.ErrInvalidConfig)
	}
	// 为当前 Bucket 和对象生成临时 GET 地址。
	output, err := s.client.Presign(ctx, &oss.GetObjectRequest{
		Bucket: oss.Ptr(s.bucket),
		Key:    oss.Ptr(objectKey),
	}, oss.PresignExpires(expires))
	// 签名失败时保留 SDK 错误链。
	if err != nil {
		return "", fmt.Errorf("sign OSS object URL: %w", err)
	}
	// 返回 SDK 生成的完整临时地址。
	return output.URL, nil
}
