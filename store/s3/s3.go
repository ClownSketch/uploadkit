// Package s3 实现 AWS S3 及兼容对象存储服务的适配器。
package s3

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClownSketch/uploadkit"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

const checksumMetadataKey = "uploadkit-sha256" // checksumMetadataKey 文件哈希元数据键

// Config 定义 AWS S3 及兼容服务初始化参数。
type Config struct {
	Region          string       // Region 存储区域
	Bucket          string       // Bucket 存储桶名称
	Endpoint        string       // Endpoint 可选的 S3 兼容服务地址
	AccessKeyID     string       // AccessKeyID 访问密钥，可为空以使用默认凭证链
	SecretAccessKey string       // SecretAccessKey 访问密钥，可为空以使用默认凭证链
	SessionToken    string       // SessionToken 可选的临时凭证令牌
	UsePathStyle    bool         // UsePathStyle 是否使用路径式 Bucket 地址
	SendSHA256      bool         // SendSHA256 是否发送 S3 SHA-256 校验头
	AllowOverwrite  bool         // AllowOverwrite 是否允许覆盖同名对象
	MaxAttempts     int          // MaxAttempts SDK 最大请求尝试次数
	HTTPClient      *http.Client // HTTPClient 可选的自定义 HTTP 客户端
}

// clientAPI 定义适配器使用的 S3 操作。
type clientAPI interface {
	PutObject(ctx context.Context, input *awss3.PutObjectInput, options ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, input *awss3.DeleteObjectInput, options ...func(*awss3.Options)) (*awss3.DeleteObjectOutput, error)
	HeadBucket(ctx context.Context, input *awss3.HeadBucketInput, options ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error)
}

// presignAPI 定义 S3 临时访问地址操作。
type presignAPI interface {
	PresignGetObject(ctx context.Context, input *awss3.GetObjectInput, options ...func(*awss3.PresignOptions)) (*awsv4.PresignedHTTPRequest, error)
}

// Store 使用 AWS 官方 SDK 保存对象。
type Store struct {
	client         clientAPI  // client S3 请求客户端
	presigner      presignAPI // presigner S3 签名客户端
	bucket         string     // bucket 存储桶名称
	sendSHA256     bool       // sendSHA256 是否发送校验头
	allowOverwrite bool       // allowOverwrite 是否允许覆盖同名对象
}

// New 创建 AWS S3 或 S3 兼容存储适配器。
// @param ctx context.Context 初始化上下文
// @param config Config 存储配置
// @return result *Store S3 存储适配器
// @return err error 配置或凭证加载错误
func New(ctx context.Context, config Config) (result *Store, err error) {
	// SDK 初始化需要可取消的上下文。
	if ctx == nil {
		return nil, uploadkit.ErrNilContext
	}
	// 规范存储区域和 Bucket 名称。
	region := strings.TrimSpace(config.Region)
	bucket := strings.TrimSpace(config.Bucket)
	// 区域和 Bucket 是 S3 请求的必需参数。
	if region == "" || bucket == "" {
		return nil, fmt.Errorf("%w: S3 region and bucket are required", uploadkit.ErrInvalidConfig)
	}
	// 清除静态凭证两端空白。
	accessKeyID := strings.TrimSpace(config.AccessKeyID)
	secretAccessKey := strings.TrimSpace(config.SecretAccessKey)
	// 静态凭证必须成对配置，否则使用默认凭证链。
	if (accessKeyID == "") != (secretAccessKey == "") {
		return nil, fmt.Errorf("%w: S3 access key is incomplete", uploadkit.ErrInvalidConfig)
	}
	// 负数重试次数无法映射到 SDK 配置。
	if config.MaxAttempts < 0 {
		return nil, fmt.Errorf("%w: S3 retry attempts are invalid", uploadkit.ErrInvalidConfig)
	}
	// 默认只设置区域，其余能力按配置追加。
	loadOptions := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	// 配置静态凭证时覆盖 SDK 默认凭证链。
	if accessKeyID != "" {
		// 创建包含可选会话令牌的静态凭证提供器。
		provider := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, strings.TrimSpace(config.SessionToken))
		// 将凭证提供器加入 SDK 加载选项。
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(provider))
	}
	// 调用方提供 HTTP Client 时复用其连接池和传输设置。
	if config.HTTPClient != nil {
		loadOptions = append(loadOptions, awsconfig.WithHTTPClient(config.HTTPClient))
	}
	// 加载 AWS 配置和默认凭证链。
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	// SDK 配置加载失败时终止适配器初始化。
	if err != nil {
		return nil, fmt.Errorf("load S3 config: %w", err)
	}
	// 规范可选的 S3 兼容服务地址。
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	// 自定义端点必须包含完整协议和主机名。
	if endpoint != "" {
		parsedEndpoint, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" {
			return nil, fmt.Errorf("%w: invalid S3 endpoint", uploadkit.ErrInvalidConfig)
		}
	}
	// 根据不可变配置创建并发安全的 S3 客户端。
	client := awss3.NewFromConfig(awsConfig, func(options *awss3.Options) {
		// 路径式地址用于部分 S3 兼容服务。
		options.UsePathStyle = config.UsePathStyle
		// 配置自定义兼容服务端点。
		if endpoint != "" {
			options.BaseEndpoint = aws.String(endpoint)
		}
		// 正数请求次数覆盖 SDK 默认重试策略。
		if config.MaxAttempts > 0 {
			options.RetryMaxAttempts = config.MaxAttempts
		}
	})
	// 保存请求客户端、签名客户端和存储桶配置。
	return &Store{
		client:         client,
		presigner:      awss3.NewPresignClient(client),
		bucket:         bucket,
		sendSHA256:     config.SendSHA256,
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
		return uploadkit.StoredObject{}, fmt.Errorf("rewind S3 object body: %w", err)
	}
	// 复制调用方元数据，避免修改上层映射。
	metadata := make(map[string]string, len(object.Metadata)+1)
	for key, value := range object.Metadata {
		metadata[key] = value
	}
	// 写入核心层确认的 SHA-256，便于下载后校验。
	metadata[checksumMetadataKey] = object.ChecksumSHA256
	// 构建一次完整的 S3 PutObject 请求。
	input := &awss3.PutObjectInput{
		Bucket:             aws.String(s.bucket),
		Key:                aws.String(object.Key),
		Body:               object.Body,
		ContentLength:      aws.Int64(object.Size),
		ContentType:        aws.String(object.ContentType),
		ContentDisposition: aws.String(object.ContentDisposition),
		Metadata:           metadata,
	}
	// 默认使用 If-None-Match 获得原子仅创建语义。
	if !s.allowOverwrite {
		input.IfNoneMatch = aws.String("*")
	}
	// 显式启用时发送 S3 标准 SHA-256 校验头。
	if s.sendSHA256 {
		// 核心层哈希是十六进制，先恢复原始字节。
		checksumBytes, decodeErr := hex.DecodeString(object.ChecksumSHA256)
		// 哈希格式异常时不发送请求。
		if decodeErr != nil {
			return uploadkit.StoredObject{}, fmt.Errorf("decode S3 SHA-256: %w", decodeErr)
		}
		// S3 校验字段使用 Base64 编码。
		input.ChecksumSHA256 = aws.String(base64.StdEncoding.EncodeToString(checksumBytes))
	}
	// 通过 SDK 写入对象并等待服务端结果。
	output, err := s.client.PutObject(ctx, input)
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		// 原子仅创建被已存在对象拒绝时返回跨适配器统一错误。
		var apiErr smithy.APIError
		if !s.allowOverwrite && errors.As(err, &apiErr) &&
			(apiErr.ErrorCode() == "PreconditionFailed" || apiErr.ErrorCode() == "ConditionalRequestConflict") {
			return uploadkit.StoredObject{}, errors.Join(uploadkit.ErrObjectExists, fmt.Errorf("put S3 object: %w", err))
		}
		return uploadkit.StoredObject{}, fmt.Errorf("put S3 object: %w", err)
	}
	// 返回服务端对象标识和版本。
	return uploadkit.StoredObject{
		ETag:      strings.Trim(aws.ToString(output.ETag), "\""),
		VersionID: aws.ToString(output.VersionId),
	}, nil
}

// Delete 删除 S3 对象；对象不存在由 S3 视为成功。
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
	_, err := s.client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	})
	// 服务端或网络错误保留原始错误链。
	if err != nil {
		return fmt.Errorf("delete S3 object: %w", err)
	}
	// S3 对不存在对象的删除保持幂等成功。
	return nil
}

// Ping 验证 S3 Bucket 和当前凭证可用。
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
	// 使用 HeadBucket 验证端点、凭证和 Bucket 权限。
	_, err := s.client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	// 检查失败时保留 SDK 错误链。
	if err != nil {
		return fmt.Errorf("check S3 bucket: %w", err)
	}
	// Bucket 当前可访问。
	return nil
}

// SignedURL 创建 S3 临时下载地址。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @param expires time.Duration 有效时间
// @return result string 临时访问地址
// @return err error 参数或签名错误
func (s *Store) SignedURL(ctx context.Context, objectKey string, expires time.Duration) (result string, err error) {
	// 存储或签名客户端为空时无法生成地址。
	if s == nil || s.presigner == nil {
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
	output, err := s.presigner.PresignGetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	}, func(options *awss3.PresignOptions) {
		// 将调用方时间长度直接交给 SDK 签名器。
		options.Expires = expires
	})
	// 签名失败时保留 SDK 错误链。
	if err != nil {
		return "", fmt.Errorf("sign S3 object URL: %w", err)
	}
	// 返回 SDK 生成的完整临时地址。
	return output.URL, nil
}
