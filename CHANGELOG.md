# Changelog

## Unreleased

- 新增保守默认策略，普通上传可直接使用 `Upload(ctx, source)`。
- 增加 MIME 禁止规则与 `*/*` 显式允许规则，禁止规则优先于允许规则。
- 增加 `UploadRequest`、`UploadManyWithPolicy` 和 `WithDefaultPolicy`，区分简洁入口与进阶配置。
- 存储适配器移除 `BaseURL`，上传结果只返回对象键和存储标识，长期访问域名由主项目决定。
- 对象键所有权收敛到 `Uploader`，存储适配器只能返回 ETag 和版本号。
- 本地存储增加 Windows 保留字符、设备名称和数据流对象键校验。
- 空 `ScannerFunc` 和 `InspectorFunc` 在初始化及直接调用时返回配置错误。
- 移除 SVG、归档和可执行文件的业务开关；类型准入统一由主项目 MIME 策略决定，内置结构检查继续保护已支持格式。

- 建立统一 `Source`、`Policy`、`Uploader` 和 `Store` API。
- 支持本地、S3、阿里云 OSS、腾讯云 COS 和华为云 OBS。
- 增加图片、SVG、ZIP 安全检查和 ClamAV 扫描器。
- 增加批量并发上传、对象删除、健康检查和临时签名地址。
- 统一存储写入参数和重复对象错误语义，签名地址有效期改用 `time.Duration`。
- 收紧 SVG、归档路径和 ZIP 容器检查，并支持 ClamAV 立即取消。
- 批量部分失败返回 `ErrBatchFailed`，同时保留逐项执行结果。
- 拒绝无效来源大小、空读取流以及同时设置 `ObjectKey` 和 `Prefix` 的歧义请求。
- 官方存储适配器在写入前主动回退内容流，本地删除补齐符号链边界检查。
- 初始化阶段立即校验显式隔离目录，避免配置错误延迟到首次上传。
