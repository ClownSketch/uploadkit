// Package tencentcos 实现腾讯云 COS 对象存储适配器。
package tencentcos

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
	"github.com/tencentyun/cos-go-sdk-v5"
)

const checksumMetadataKey = "x-cos-meta-uploadkit-sha256" // checksumMetadataKey 文件哈希元数据键

// Config 定义腾讯云 COS 初始化参数。
type Config struct {
	Region         string        // Region Bucket 所在区域
	Bucket         string        // Bucket 完整存储桶名称，包含 AppID
	Endpoint       string        // Endpoint 可选的自定义 Bucket 地址
	SecretID       string        // SecretID 访问密钥 ID
	SecretKey      string        // SecretKey 访问密钥
	SessionToken   string        // SessionToken 可选的临时凭证令牌
	AllowOverwrite bool          // AllowOverwrite 是否允许覆盖同名对象
	DisableCRC     bool          // DisableCRC 是否关闭默认 CRC64 校验
	RetryCount     int           // RetryCount SDK 最大请求次数
	RetryInterval  time.Duration // RetryInterval SDK 重试间隔
	HTTPClient     *http.Client  // HTTPClient 可选的自定义 HTTP 客户端
}

// Store 使用腾讯云官方 SDK 保存对象。
type Store struct {
	client         *cos.Client // client COS 请求客户端
	allowOverwrite bool        // allowOverwrite 是否允许覆盖同名对象
}

// New 创建腾讯云 COS 存储适配器。
// @param config Config 存储配置
// @return result *Store COS 存储适配器
// @return err error 配置错误
func New(config Config) (result *Store, err error) {
	// 规范 Bucket、区域和静态凭证。
	bucket := strings.TrimSpace(config.Bucket)
	region := strings.TrimSpace(config.Region)
	secretID := strings.TrimSpace(config.SecretID)
	secretKey := strings.TrimSpace(config.SecretKey)
	// Bucket 和静态凭证是 COS 请求的必需参数。
	if bucket == "" || secretID == "" || secretKey == "" {
		return nil, fmt.Errorf("%w: COS bucket and credentials are required", uploadkit.ErrInvalidConfig)
	}
	// 重试次数和间隔不能为负数。
	if config.RetryCount < 0 || config.RetryInterval < 0 {
		return nil, fmt.Errorf("%w: COS retry config is invalid", uploadkit.ErrInvalidConfig)
	}
	// 规范可选的 COS 自定义端点。
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	// bucketURL 保存最终使用的 Bucket 访问地址。
	var bucketURL *url.URL
	// 未配置自定义端点时根据区域和 Bucket 生成官方地址。
	if endpoint == "" {
		// 官方地址生成必须提供区域。
		if region == "" {
			return nil, fmt.Errorf("%w: COS region is required without endpoint", uploadkit.ErrInvalidConfig)
		}
		// 使用官方 SDK 生成 HTTPS Bucket 地址。
		bucketURL, err = cos.NewBucketURL(bucket, region, true)
		// Bucket 名称或区域非法时终止初始化。
		if err != nil {
			return nil, fmt.Errorf("create COS bucket URL: %w", err)
		}
	} else {
		// 自定义端点必须是完整 URL。
		bucketURL, err = url.Parse(endpoint)
		// 端点必须包含协议和主机名。
		if err != nil || bucketURL.Scheme == "" || bucketURL.Host == "" {
			return nil, fmt.Errorf("%w: invalid COS endpoint", uploadkit.ErrInvalidConfig)
		}
	}
	// 默认使用独立的标准 HTTP Client。
	httpClient := &http.Client{}
	// 调用方提供 Client 时复制配置，避免修改原对象的 Transport。
	if config.HTTPClient != nil {
		clientCopy := *config.HTTPClient
		httpClient = &clientCopy
	}
	// 保存调用方原有 Transport，交给签名 Transport 继续使用。
	baseTransport := httpClient.Transport
	// 使用官方签名 Transport 包装所有 COS 请求。
	httpClient.Transport = &cos.AuthorizationTransport{
		SecretID:     secretID,
		SecretKey:    secretKey,
		SessionToken: strings.TrimSpace(config.SessionToken),
		Transport:    baseTransport,
	}
	// 创建可并发复用的 COS 客户端。
	client := cos.NewClient(&cos.BaseURL{BucketURL: bucketURL}, httpClient)
	// 默认启用 SDK CRC64 完整性校验。
	client.Conf.EnableCRC = !config.DisableCRC
	// 启用 SDK 对对象键的结构检查。
	client.Conf.ObjectKeySimplifyCheck = true
	// 正数请求次数覆盖 SDK 默认重试策略。
	if config.RetryCount > 0 {
		client.Conf.RetryOpt.Count = config.RetryCount
	}
	// 正数重试间隔覆盖 SDK 默认等待时间。
	if config.RetryInterval > 0 {
		client.Conf.RetryOpt.Interval = config.RetryInterval
	}
	// 保存客户端和覆盖策略。
	return &Store{
		client:         client,
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
		return uploadkit.StoredObject{}, fmt.Errorf("rewind COS object body: %w", err)
	}
	// 将调用方元数据转换为 COS 请求头。
	metadata := make(http.Header, len(object.Metadata)+1)
	for key, value := range object.Metadata {
		metadata.Set("x-cos-meta-"+key, value)
	}
	// 写入核心层确认的 SHA-256，便于下载后校验。
	metadata.Set(checksumMetadataKey, object.ChecksumSHA256)
	// extraHeaders 保存条件写入等附加请求头。
	extraHeaders := make(http.Header)
	// 默认使用 If-None-Match 获得原子仅创建语义。
	if !s.allowOverwrite {
		extraHeaders.Set("If-None-Match", "*")
	}
	// 通过 SDK 写入对象并等待服务端响应。
	response, err := s.client.Object.Put(ctx, object.Key, object.Body, &cos.ObjectPutOptions{
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentDisposition: object.ContentDisposition,
			ContentType:        object.ContentType,
			ContentLength:      object.Size,
			XCosMetaXXX:        &metadata,
			XOptionHeader:      &extraHeaders,
		},
	})
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		// 原子仅创建被已存在对象拒绝时返回跨适配器统一错误。
		var responseErr *cos.ErrorResponse
		if !s.allowOverwrite && errors.As(err, &responseErr) && responseErr.Response != nil &&
			(responseErr.Response.StatusCode == http.StatusConflict || responseErr.Response.StatusCode == http.StatusPreconditionFailed) {
			return uploadkit.StoredObject{}, errors.Join(uploadkit.ErrObjectExists, fmt.Errorf("put COS object: %w", err))
		}
		return uploadkit.StoredObject{}, fmt.Errorf("put COS object: %w", err)
	}
	// 成功请求必须返回可读取的 HTTP 响应。
	if response == nil || response.Response == nil {
		return uploadkit.StoredObject{}, errors.New("put COS object: empty response")
	}
	// 读取响应头后关闭响应体，释放连接复用资源。
	defer response.Body.Close()
	// 返回服务端对象标识和版本。
	return uploadkit.StoredObject{
		ETag:      strings.Trim(response.Header.Get("ETag"), "\""),
		VersionID: response.Header.Get("x-cos-version-id"),
	}, nil
}

// Delete 删除 COS 对象；对象不存在由 COS 视为成功。
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
	response, err := s.client.Object.Delete(ctx, objectKey)
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		return fmt.Errorf("delete COS object: %w", err)
	}
	// 关闭可选响应体，释放连接复用资源。
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	// COS 对不存在对象的删除保持幂等成功。
	return nil
}

// Ping 验证 COS Bucket 和当前凭证可用。
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
	// 使用 HeadBucket 验证端点、凭证和访问权限。
	response, err := s.client.Bucket.Head(ctx)
	// 检查失败时保留 SDK 错误链。
	if err != nil {
		return fmt.Errorf("check COS bucket: %w", err)
	}
	// 关闭可选响应体，释放连接复用资源。
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	// Bucket 当前可访问。
	return nil
}

// SignedURL 创建 COS 临时下载地址。
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
	// 为当前对象生成临时 GET 地址。
	signedURL, err := s.client.Object.GetPresignedURL2(ctx, http.MethodGet, objectKey, expires, nil)
	// 签名失败时保留 SDK 错误链。
	if err != nil {
		return "", fmt.Errorf("sign COS object URL: %w", err)
	}
	// 返回 URL 对象的完整字符串。
	return signedURL.String(), nil
}
