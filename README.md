# uploadkit

`uploadkit` 是面向 Go 服务端的文件上传工具。它负责读取不同来源的文件、限制实际大小、识别真实类型、执行基础结构检查、调用可选扫描器，并将文件写入统一的存储适配器。

文件是否符合具体业务、对象键如何归属用户、上传结果如何入库以及访问域名如何组织，均由主项目决定。

## 特性

- 统一支持本地文件系统、AWS S3/S3 兼容服务、阿里云 OSS、腾讯云 COS 和华为云 OBS。
- 支持 `multipart.FileHeader`、`[]byte`、`io.Reader`、`io.ReadSeeker`、本地路径、`*os.File` 和 `fs.FS`。
- 先写入有界隔离文件，再按实际内容识别 MIME、计算 SHA-256 并执行检查。
- 提供保守默认策略，主项目可按上传场景覆盖允许类型、禁止类型和大小限制。
- 内置图片像素、SVG 主动内容以及 ZIP 类容器的路径穿越、符号链接、嵌套归档和压缩炸弹检查。
- 提供进程内离线扫描器与 ClamAV INSTREAM 扫描器，并开放 `Scanner`、`Inspector` 扩展接口。
- 支持请求级追加 `Inspector`；实例强制扫描不能被单次 Policy 覆盖关闭。
- 上传器可并发复用，批量上传保持输入顺序并限制同时隔离的文件数。
- 默认对象键使用 UTC 日期目录和 128 位安全随机名称，不信任客户端文件路径。
- 上传结果只返回 `ObjectKey`、文件事实和存储标识，不绑定主项目访问域名。

## 安装

```bash
go get github.com/ClownSketch/uploadkit
```

## 快速开始

默认策略允许 PDF、JPEG、PNG、WebP 和纯文本，单文件上限为 10 MiB，单批最多 10 个文件。

```go
package main

import (
	"context"
	"log"

	"github.com/ClownSketch/uploadkit"
	"github.com/ClownSketch/uploadkit/store/local"
)

func main() {
	store, err := local.New(local.Config{Root: "./storage/uploads"})
	if err != nil {
		log.Fatal(err)
	}

	uploader, err := uploadkit.New(store)
	if err != nil {
		log.Fatal(err)
	}

	result, err := uploader.Upload(
		context.Background(),
		uploadkit.FromBytes("notice.txt", []byte("hello uploadkit")),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key=%s mime=%s size=%d", result.ObjectKey, result.MIMEType, result.Size)
}
```

完整可运行代码见 [`examples/basic`](examples/basic/main.go)。

## 主项目定义策略

主项目可以为头像、合同、数据导入等场景分别创建策略。拒绝规则优先于允许规则；两组规则都支持完整 MIME、`type/*`，允许列表还可显式使用 `*/*`。

```go
policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
	MaxFileSize:      5 << 20,
	MaxFiles:         5,
	AllowedMIMETypes: []string{"image/*"},
	DeniedMIMETypes:  []string{"image/svg+xml"},
	MaxImagePixels:   25_000_000,
})
if err != nil {
	return err
}

uploader, err := uploadkit.New(
	store,
	uploadkit.WithDefaultPolicy(policy),
)
```

需要为单次上传指定前缀、固定对象键、元数据或临时策略时，使用进阶入口：

```go
result, err := uploader.UploadRequest(ctx, uploadkit.Request{
	Source: uploadkit.FromBytes("avatar.png", content),
	Policy: policy,
	Prefix: "tenant/avatar",
	Metadata: map[string]string{
		"tenant-id": tenantID,
	},
})
```

## 更换存储

上传流程不随存储厂商变化，只替换 `Store` 初始化：

```go
store, err := s3.New(ctx, s3.Config{
	Region:          "ap-southeast-1",
	Bucket:          "example-bucket",
	AccessKeyID:     "...",
	SecretAccessKey: "...",
})

uploader, err := uploadkit.New(store)
```

其他初始化方式见 [存储适配器文档](docs/ADAPTERS.md)。

## 上传流程

```text
Source
  -> 实际大小受限的本地隔离
  -> 真实 MIME 与扩展名校验
  -> 图片 / SVG / ZIP 类容器检查
  -> 实例 Inspector -> 请求 Inspector
  -> 必需 Scanner
  -> 安全对象键
  -> Store.Put
```

成功返回表示内容已通过全部必需检查并写入存储，不是“先接收后扫描”。`Store.Put` 负责清理自身未完成的写入。核心上传器不会在写入错误后猜测远端状态并删除对象，避免误删同键既有数据。

普通上传保持现有签名；特殊用途可追加本次检查：

```go
return uploader.UploadRequest(ctx, req.WithInspectors(receiptQRInspector))
```

`WithInspectors` 追加、不替换，返回请求副本。生产扫描器在启动时装配；详见 [离线扫描器](docs/OFFLINE_SCANNER.md)。

## 输入来源

| 来源 | 构造方法 | 说明 |
| --- | --- | --- |
| multipart | `FromMultipart` | 标准 HTTP 文件上传 |
| 内存字节 | `FromBytes` | 复制输入，可重复打开 |
| 数据流 | `FromReader` | 一次性来源，只能上传一次 |
| 可回退流 | `FromReadSeeker` | 可重复使用，共享读取生命周期会串行化 |
| 本地路径 | `FromPath` | 上传时重新打开文件 |
| 文件对象 | `FromFile` | 通过真实路径重新打开 |
| 文件系统 | `FromFS` | 支持 `embed.FS`、`os.DirFS` 等 |

核心库不直接拉取远程 URL。SSRF、DNS 重绑定、重定向、内网地址和下载上限应由主项目或独立下载组件处理，再将受控数据交给 `uploadkit`。

## 对象访问

上传结果中的 `ObjectKey` 适合持久化。公开访问地址由主项目在读取记录时使用自己的域名拼接：

```go
publicURL := fileHost + "/" + result.ObjectKey
```

私有对象可按需创建临时签名地址：

```go
signedURL, err := uploader.SignedURL(ctx, objectKey, 5*time.Minute)
```

对象删除和存储健康检查分别使用：

```go
err := uploader.Delete(ctx, objectKey)
err = uploader.Ping(ctx)
```

不支持签名地址或健康检查的 Store 会返回 `ErrSignedURLUnsupported` 或 `ErrHealthCheckUnsupported`。

## 安全说明

MIME 准入只是第一层规则，不等于文件没有威胁。面向不可信来源时建议：

1. Bucket 默认私有，下载使用独立域名或临时签名地址。
2. 在默认策略启用 `RequireMalwareScanner`，并注册离线规则引擎和/或 ClamAV；初始化失败不要降级放行。
3. 主项目按场景维护允许类型，不接受客户端决定存储端点、凭证、对象根前缀、插件名或跳过标志。
4. Web 服务、反向代理和上传策略同时设置大小上限。
5. 数据库只保存对象键和业务关系；上传失败不创建业务记录。

完整边界见 [SECURITY.md](SECURITY.md)。

## 文档

- [API 使用说明](docs/API.md)
- [离线扫描器](docs/OFFLINE_SCANNER.md)
- [存储适配器](docs/ADAPTERS.md)
- [安全模型](SECURITY.md)
- [版本记录](CHANGELOG.md)

## 许可证

[MIT License](LICENSE)
