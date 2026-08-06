# API 使用说明

## 核心对象

- `Source`：描述文件名称、大小和读取方式。
- `Policy`：描述工具层限制以及主项目允许、禁止的真实 MIME。
- `Uploader`：组织隔离、检查、扫描和存储写入。
- `Store`：隐藏本地文件系统与对象存储差异。

## 默认策略

`uploadkit.DefaultPolicy()` 返回保守默认策略：

- 单文件最大 10 MiB。
- 单批最多 10 个文件。
- 允许 `application/pdf`、`image/jpeg`、`image/png`、`image/webp` 和 `text/plain`。
- 图片最大 100,000,000 像素。
- ZIP 类容器最多 1,000 个条目、512 MiB 解压总量和 200 倍压缩比。
- 默认禁止嵌套归档，不强制要求扫描器。

最简上传入口自动使用当前 `Uploader` 的默认策略：

```go
result, err := uploader.Upload(ctx, source)
```

## 创建自定义策略

策略必须通过 `NewPolicy` 创建，创建后可被多个 goroutine 只读复用。

```go
policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
	MaxFileSize:             20 << 20,
	MaxFiles:                10,
	AllowedMIMETypes:        []string{"image/*", "application/pdf"},
	DeniedMIMETypes:         []string{"image/svg+xml"},
	IgnoreExtensionMismatch: false,
	AllowNestedArchives:     false,
	RequireMalwareScanner:   true,
	MaxImagePixels:          40_000_000,
	MaxArchiveFiles:         500,
	MaxArchiveExpandedBytes: 256 << 20,
	MaxCompressionRatio:     100,
})
```

MIME 规则支持：

- 精确类型，如 `application/pdf`。
- 主类型通配，如 `image/*`。
- 显式允许全部类型的 `*/*`。

`DeniedMIMETypes` 始终优先于 `AllowedMIMETypes`。未配置允许列表时，`NewPolicy` 使用内置保守列表；主项目不需要为了常见文件重复定义基础策略。

`AllowedMIMETypes` 只决定文件能否进入后续检查。图片、SVG 和 ZIP 类容器在获准后仍执行内置结构检查。其他格式可以通过 `WithInspector` 或 `WithScanner` 补充检查。

## 创建上传器

```go
uploader, err := uploadkit.New(
	store,
	uploadkit.WithDefaultPolicy(policy),
	uploadkit.WithTempDir("/var/lib/app/upload-quarantine"),
	uploadkit.WithMaxConcurrency(16),
	uploadkit.WithScanner(scanner),
	uploadkit.WithCleanupErrorHandler(func(err error) {
		logger.Error("cleanup upload quarantine", err)
	}),
)
```

| 选项 | 作用 |
| --- | --- |
| `WithDefaultPolicy` | 替换当前上传器默认策略 |
| `WithTempDir` | 指定已存在的隔离文件目录 |
| `WithMaxConcurrency` | 限制单个上传器同时处理的文件数 |
| `WithKeyGenerator` | 替换默认随机对象键生成器 |
| `WithScanner` | 按注册顺序增加扫描器 |
| `WithInspector` | 按注册顺序增加结构检查器 |
| `WithCleanupErrorHandler` | 接收上传结束后的临时文件清理错误 |

上传器创建后保持只读，可注册为应用级共享实例。注入的 Store、Scanner、Inspector 和 KeyGenerator 也必须支持并发调用。

注册到同一个 `Uploader` 的 Scanner 会检查该实例处理的全部文件。`RequireMalwareScanner` 用于保证当前策略执行时已经配置扫描器；不同信任级别应使用独立的 `Uploader` 实例。

## 上传单个文件

### 简洁入口

```go
source, err := uploadkit.FromMultipart(fileHeader)
if err != nil {
	return err
}

result, err := uploader.Upload(ctx, source)
```

### 进阶入口

需要指定策略、对象位置或元数据时使用 `UploadRequest`：

```go
result, err := uploader.UploadRequest(ctx, uploadkit.Request{
	Source:             source,
	Policy:             avatarPolicy,
	Prefix:             "tenant/avatar",
	ContentDisposition: "attachment",
	Metadata: map[string]string{
		"tenant-id": tenantID,
	},
})
```

`Request.Policy` 为零值时沿用上传器默认策略。

`Request.ObjectKey` 可指定完整对象键并绕过默认生成器，但仍执行对象键校验。`ObjectKey` 和 `Prefix` 不能同时设置；普通用户上传应优先使用受控 `Prefix` 和默认随机键。

成功结果只返回文件事实和存储标识：

```go
type Result struct {
	OriginalName   string
	ObjectKey      string
	MIMEType       string
	Size           int64
	ChecksumSHA256 string
	ETag           string
	VersionID      string
}
```

组件不生成长期访问地址。主项目可以保存 `ObjectKey`，在响应数据时按自己的域名和权限规则生成访问地址。

## 批量上传

使用默认策略：

```go
batch, err := uploader.UploadMany(ctx, sources)
```

使用指定策略：

```go
batch, err := uploader.UploadManyWithPolicy(ctx, sources, policy)
```

每个文件需要不同策略、前缀或元数据：

```go
batch, err := uploader.UploadBatch(ctx, []uploadkit.Request{
	{Source: avatar, Policy: imagePolicy, Prefix: "avatar"},
	{Source: contract, Policy: pdfPolicy, Prefix: "contract"},
})
```

`BatchResult.Items` 与输入顺序一致。单项失败保存在对应 `BatchItem.Err` 中；存在失败时，顶层错误可通过 `errors.Is(err, uploadkit.ErrBatchFailed)` 判断。整体参数错误和上下文取消保留原始错误语义。

## 自定义扫描器

```go
scanner := uploadkit.ScannerFunc(func(
	ctx context.Context,
	file uploadkit.FileInfo,
	content io.Reader,
) (uploadkit.ScanResult, error) {
	return uploadkit.ScanResult{Clean: true}, nil
})
```

扫描器获得位于文件起点的只读内容。返回错误表示扫描未可靠完成；`Clean=false` 或非空 `Threat` 表示发现威胁，两者都会停止上传。

## 自定义检查器

`Inspector` 适合检查主项目特有的文件结构，例如导入模板列或媒体容器：

```go
inspector := uploadkit.InspectorFunc(func(
	ctx context.Context,
	file uploadkit.FileInfo,
	content io.Reader,
) error {
	return validateDocument(content)
})
```

`Inspector` 只负责文件内容检查，不应查询业务权限或写入业务记录。

## 实现自定义 Store

```go
type Store interface {
	Put(ctx context.Context, object uploadkit.PutObject) (uploadkit.StoredObject, error)
	Delete(ctx context.Context, objectKey string) error
}
```

实现约束：

1. `Put` 调用 `uploadkit.ValidatePutObject` 校验统一写入参数。
2. `Put` 从 `object.Body` 起点读取并按 `object.Size` 校验完整性。
3. `Put` 返回错误前自行清理未完成写入，不依赖核心层猜测远端状态。
4. `Delete` 对不存在对象幂等成功。
5. `StoredObject` 只返回 ETag 和版本号；对象键始终由 `Uploader` 生成或校验。
6. 支持临时地址时实现 `URLSigner`，支持主动检查时实现 `HealthChecker`。

```go
signedURL, err := uploader.SignedURL(ctx, objectKey, 5*time.Minute)
err = uploader.Ping(ctx)
```

## 错误判断

公开错误支持 `errors.Is`：

```go
if errors.Is(err, uploadkit.ErrFileTooLarge) {
	return handleFileTooLarge()
}
```

常用错误包括 `ErrInvalidSource`、`ErrFileTooLarge`、`ErrMIMETypeNotAllowed`、`ErrExtensionMismatch`、`ErrThreatDetected`、`ErrUnsafeSVG`、`ErrUnsafeArchive`、`ErrObjectExists` 和 `ErrBatchFailed`。

## 并发约束

- `Uploader` 和 `Policy` 可被多个 goroutine 并发复用。
- `FromBytes`、`FromPath`、`FromFile`、`FromFS` 和 `FromMultipart` 每次打开独立内容流。
- `FromReadSeeker` 可重复使用，共享 Reader 的完整读取生命周期会串行化。
- `FromReader` 是一次性来源，只能由一个上传请求消费。
- `WithCleanupErrorHandler` 在当前上传调用中同步执行，不应执行长时间阻塞操作。
