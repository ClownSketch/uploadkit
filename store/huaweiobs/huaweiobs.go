// Package huaweiobs 实现华为云 OBS 对象存储适配器。
package huaweiobs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClownSketch/uploadkit"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

const checksumMetadataKey = "uploadkit-sha256" // checksumMetadataKey 文件哈希元数据键

// Config 定义华为云 OBS 初始化参数。
type Config struct {
	Region          string       // Region Bucket 所在区域
	Bucket          string       // Bucket 存储桶名称
	Endpoint        string       // Endpoint OBS 访问地址
	AccessKeyID     string       // AccessKeyID 访问密钥 ID
	SecretAccessKey string       // SecretAccessKey 访问密钥
	SecurityToken   string       // SecurityToken 可选的临时凭证令牌
	UsePathStyle    bool         // UsePathStyle 是否使用路径式 Bucket 地址
	UseCName        bool         // UseCName Endpoint 是否为自定义域名
	MaxRetries      int          // MaxRetries SDK 最大重试次数
	HTTPClient      *http.Client // HTTPClient 可选的共享 HTTP 客户端
}

// Store 使用华为云官方 SDK 保存对象。
// 华为 SDK 的请求上下文属于客户端配置，因此每次操作创建轻量客户端并复用 HTTP 连接池。
type Store struct {
	region          string       // region Bucket 所在区域
	bucket          string       // bucket 存储桶名称
	endpoint        string       // endpoint OBS 访问地址
	accessKeyID     string       // accessKeyID 访问密钥 ID
	secretAccessKey string       // secretAccessKey 访问密钥
	securityToken   string       // securityToken 临时凭证令牌
	usePathStyle    bool         // usePathStyle 是否使用路径式地址
	useCName        bool         // useCName 是否使用自定义域名
	maxRetries      int          // maxRetries SDK 最大重试次数
	httpClient      *http.Client // httpClient 共享 HTTP 连接池
}

// New 创建华为云 OBS 存储适配器。
// @param config Config 存储配置
// @return result *Store OBS 存储适配器
// @return err error 配置错误
func New(config Config) (result *Store, err error) {
	// 规范 Bucket、端点和静态凭证。
	bucket := strings.TrimSpace(config.Bucket)
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	accessKeyID := strings.TrimSpace(config.AccessKeyID)
	secretAccessKey := strings.TrimSpace(config.SecretAccessKey)
	// Bucket、端点和凭证是 OBS 客户端的必需参数。
	if bucket == "" || endpoint == "" || accessKeyID == "" || secretAccessKey == "" {
		return nil, fmt.Errorf("%w: OBS bucket, endpoint and credentials are required", uploadkit.ErrInvalidConfig)
	}
	// 端点必须包含完整协议和主机名。
	parsedEndpoint, parseErr := url.Parse(endpoint)
	if parseErr != nil || parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" {
		return nil, fmt.Errorf("%w: invalid OBS endpoint", uploadkit.ErrInvalidConfig)
	}
	// 路径式和 CNAME 地址不能同时启用，重试次数不能为负数。
	if config.MaxRetries < 0 || (config.UsePathStyle && config.UseCName) {
		return nil, fmt.Errorf("%w: OBS retry count is invalid", uploadkit.ErrInvalidConfig)
	}
	// 零值使用明确的三次 SDK 重试上限。
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	// 默认创建可复用连接池的标准 HTTP Client。
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	// 保存不可变配置，操作阶段按上下文创建轻量 SDK 客户端。
	return &Store{
		region:          strings.TrimSpace(config.Region),
		bucket:          bucket,
		endpoint:        endpoint,
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		securityToken:   strings.TrimSpace(config.SecurityToken),
		usePathStyle:    config.UsePathStyle,
		useCName:        config.UseCName,
		maxRetries:      config.MaxRetries,
		httpClient:      httpClient,
	}, nil
}

// Put 保存已经通过 uploadkit 检查的对象。
// @param ctx context.Context 调用上下文
// @param object uploadkit.PutObject 待保存对象
// @return result uploadkit.StoredObject 存储结果
// @return err error SDK 写入错误
func (s *Store) Put(ctx context.Context, object uploadkit.PutObject) (result uploadkit.StoredObject, err error) {
	// 空存储对象无法执行写入。
	if s == nil {
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
		return uploadkit.StoredObject{}, fmt.Errorf("rewind OBS object body: %w", err)
	}
	// 为本次请求创建绑定上下文的 SDK 客户端。
	client, err := s.client(ctx)
	if err != nil {
		return uploadkit.StoredObject{}, err
	}
	// 复制调用方元数据，避免修改上层映射。
	metadata := make(map[string]string, len(object.Metadata)+1)
	for key, value := range object.Metadata {
		metadata[key] = value
	}
	// 写入核心层确认的 SHA-256，便于下载后校验。
	metadata[checksumMetadataKey] = object.ChecksumSHA256
	// 通过 SDK 写入对象并等待服务端结果。
	output, err := client.PutObject(&obs.PutObjectInput{
		PutObjectBasicInput: obs.PutObjectBasicInput{
			ObjectOperationInput: obs.ObjectOperationInput{
				Bucket:   s.bucket,
				Key:      object.Key,
				Metadata: metadata,
			},
			HttpHeader: obs.HttpHeader{
				ContentDisposition: object.ContentDisposition,
				ContentType:        object.ContentType,
			},
			ContentSHA256: object.ChecksumSHA256,
			ContentLength: object.Size,
		},
		Body: object.Body,
	})
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("put OBS object: %w", err)
	}
	// 返回服务端对象标识和版本。
	return uploadkit.StoredObject{
		ETag:      strings.Trim(output.ETag, "\""),
		VersionID: output.VersionId,
	}, nil
}

// Delete 删除 OBS 对象；对象不存在由 OBS 视为成功。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @return err error SDK 删除错误
func (s *Store) Delete(ctx context.Context, objectKey string) error {
	// 空存储对象无法执行删除。
	if s == nil {
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
	// 为本次请求创建绑定上下文的 SDK 客户端。
	client, err := s.client(ctx)
	if err != nil {
		return err
	}
	// 向当前 Bucket 提交删除请求。
	_, err = client.DeleteObject(&obs.DeleteObjectInput{Bucket: s.bucket, Key: objectKey})
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		return fmt.Errorf("delete OBS object: %w", err)
	}
	// OBS 对不存在对象的删除保持幂等成功。
	return nil
}

// Ping 验证 OBS Bucket 和当前凭证可用。
// @param ctx context.Context 调用上下文
// @return err error SDK 检查错误
func (s *Store) Ping(ctx context.Context) error {
	// 空存储对象无法执行检查。
	if s == nil {
		return uploadkit.ErrNilStore
	}
	// 健康检查统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ErrNilContext
	}
	// 为本次请求创建绑定上下文的 SDK 客户端。
	client, err := s.client(ctx)
	if err != nil {
		return err
	}
	// 使用 HeadBucket 验证端点、凭证和访问权限。
	_, err = client.HeadBucket(s.bucket)
	// 检查失败时保留 SDK 错误链。
	if err != nil {
		return fmt.Errorf("check OBS bucket: %w", err)
	}
	// Bucket 当前可访问。
	return nil
}

// SignedURL 创建 OBS 临时下载地址。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @param expires time.Duration 有效时间
// @return result string 临时访问地址
// @return err error 参数或签名错误
func (s *Store) SignedURL(ctx context.Context, objectKey string, expires time.Duration) (result string, err error) {
	// 空存储对象无法生成签名地址。
	if s == nil {
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
	// OBS 只接受整秒，非整秒有效期向上取整，避免实际时间短于调用方要求。
	expiresSeconds := int64(expires / time.Second)
	if expires%time.Second != 0 {
		expiresSeconds++
	}
	// 转换前校验当前平台 int 上限。
	if expiresSeconds <= 0 || expiresSeconds > int64(^uint(0)>>1) {
		return "", fmt.Errorf("%w: signed URL expiry is invalid", uploadkit.ErrInvalidConfig)
	}
	// 为本次请求创建绑定上下文的 SDK 客户端。
	client, err := s.client(ctx)
	if err != nil {
		return "", err
	}
	// 为当前 Bucket 和对象生成临时 GET 地址。
	output, err := client.CreateSignedUrl(&obs.CreateSignedUrlInput{
		Method:  obs.HTTP_GET,
		Bucket:  s.bucket,
		Key:     objectKey,
		Expires: int(expiresSeconds),
	})
	// 签名失败时保留 SDK 错误链。
	if err != nil {
		return "", fmt.Errorf("sign OBS object URL: %w", err)
	}
	// 返回 SDK 生成的完整临时地址。
	return output.SignedUrl, nil
}

// client 创建绑定本次调用上下文的轻量 OBS 客户端。
// @description HTTP 客户端由 Store 复用，避免为每次请求新建连接池
// @param ctx context.Context 调用上下文
// @return result *obs.ObsClient OBS 客户端
// @return err error 初始化错误
func (s *Store) client(ctx context.Context) (result *obs.ObsClient, err error) {
	// SDK 将请求上下文放在客户端配置中，因此每次操作创建轻量客户端。
	client, err := obs.New(
		s.accessKeyID,
		s.secretAccessKey,
		s.endpoint,
		obs.WithRequestContext(ctx),
		obs.WithHttpClient(s.httpClient),
		obs.WithPathStyle(s.usePathStyle),
		obs.WithCustomDomainName(s.useCName),
		obs.WithRegion(s.region),
		obs.WithSecurityToken(s.securityToken),
		obs.WithMaxRetryCount(s.maxRetries),
	)
	// 客户端配置失败时保留 SDK 错误链。
	if err != nil {
		return nil, fmt.Errorf("create OBS client: %w", err)
	}
	// 返回共享同一个 HTTP 连接池的轻量客户端。
	return client, nil
}
