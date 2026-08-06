# 存储适配器

所有适配器都实现 `uploadkit.Store`。业务侧完成初始化后统一调用 `uploadkit.New(store)`。

官方适配器在写入前都会校验 `PutObject`，并将可回退内容流恢复到起点。调用方不需要维护 `Body` 的当前游标。

## 本地文件系统

```go
store, err := local.New(local.Config{
	Root:           "/var/lib/app/uploads",
	AllowOverwrite: false,
})
```

本地适配器逐级校验对象目录，先在目标目录创建临时文件，完整写入并执行 `fsync` 后再原子提交。默认拒绝覆盖，并检查对象目录不能通过符号链接逃逸根目录。

## AWS S3 和 S3 兼容服务

AWS 默认凭证链：

```go
store, err := s3.New(ctx, s3.Config{
	Region: "ap-southeast-1",
	Bucket: "example-bucket",
})
```

MinIO、Cloudflare R2 等 S3 兼容服务：

```go
store, err := s3.New(ctx, s3.Config{
	Region:          "auto",
	Bucket:          "example-bucket",
	Endpoint:        "https://object.example.com",
	AccessKeyID:     "...",
	SecretAccessKey: "...",
	UsePathStyle:    true,
})
```

`SendSHA256` 可以显式发送 S3 SHA-256 校验头；兼容服务不支持该头时保持关闭。文件 SHA-256 始终写入 `uploadkit-sha256` 元数据。

## 阿里云 OSS

```go
store, err := aliyunoss.New(aliyunoss.Config{
	Region:          "cn-hangzhou",
	Bucket:          "example-bucket",
	AccessKeyID:     "...",
	AccessKeySecret: "...",
})
```

支持默认凭证链、STS `SecurityToken`、自定义 Endpoint、CNAME 和路径式地址。`UseCName` 与 `UsePathStyle` 不能同时开启。

配置静态 STS 令牌时，令牌到期后需要重新创建 Store；需要自动轮换时应使用 SDK 默认凭证链。

## 腾讯云 COS

```go
store, err := tencentcos.New(tencentcos.Config{
	Region:    "ap-guangzhou",
	Bucket:    "example-1250000000",
	SecretID:  "...",
	SecretKey: "...",
})
```

COS 默认启用 CRC64 完整性校验。仅在服务端不支持时设置 `DisableCRC=true`。

当前 COS 配置保存静态临时凭证。临时凭证到期后应使用新凭证重新创建 Store。

## 华为云 OBS

```go
store, err := huaweiobs.New(huaweiobs.Config{
	Region:          "cn-north-4",
	Bucket:          "example-bucket",
	Endpoint:        "https://obs.cn-north-4.myhuaweicloud.com",
	AccessKeyID:     "...",
	SecretAccessKey: "...",
})
```

华为官方 SDK 将请求上下文绑定在客户端配置中。适配器为每次操作创建轻量 SDK 客户端，但复用同一个 `http.Client` 和连接池，因此每个业务请求都能正确取消，不会为每次上传新建 TCP 连接池。

华为 OBS 当前适配器不承诺固定对象键的原子“仅创建”语义。生产上传应保持默认随机对象键；确需使用 `Request.ObjectKey` 时，由业务保证对象键唯一，或在 Bucket 侧开启版本控制并保留审计记录。

当前 OBS 配置保存静态临时凭证。临时凭证到期后应使用新凭证重新创建 Store。

## 对象键与访问地址

所有适配器只返回 ETag 和版本号，不接收主项目的访问域名，也不能改写对象键。主项目应持久化 `Result.ObjectKey`，并在输出数据时按自己的域名、租户和权限规则生成公开地址。

私有 Bucket 可按需创建临时签名地址：

```go
signedURL, err := uploader.SignedURL(ctx, objectKey, 5*time.Minute)
```

不要把长期云凭证发送给前端。浏览器直传需要由主项目单独设计短期凭证、对象键范围、大小、MIME 和回调校验，不属于本库服务端上传 API 的职责。
