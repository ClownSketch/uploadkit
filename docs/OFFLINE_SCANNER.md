# 离线扫描器

`scanner/offline` 是进程内、离线、同步的自研扫描引擎。它复用 `uploadkit.Scanner` 契约，不另造插件体系，也不依赖 clamd 或在线查杀服务。

## 成功语义

`UploadRequest` 返回成功，表示本次上传内容已经通过所有必需检查，并已写入存储。不是“文件已接收，后续再扫描”。

扫描或检查期间不返回可用对象标识，不生成公开地址。命中、拒绝、读取失败、超限、超时或取消都不会进入 `Store.Put`。

## 错误区分

| 情况 | 错误 | 上层建议 |
| --- | --- | --- |
| 规则命中威胁 | `ErrThreatDetected` | 拒绝上传，不重试同一内容 |
| 当前 MIME 没有任何适用规则 | `ErrScanIncomplete` | 补齐规则覆盖或收紧上传 MIME；不可当作通过 |
| 扫描未可靠完成 | `ErrScanIncomplete` | 可按运维策略重试或转人工 |
| 上下文取消/超时 | `context.Canceled` / `context.DeadlineExceeded` | 按调用方语义中止或重试 |

“检查后未命中”要求至少有一条适用于该真实 MIME 的摘要或字节规则，并且这些规则全部执行完毕且未命中。没有任何适用规则时属于“无法检查”，不能返回清洁通过。纯摘要规则包在摘要未命中时仍可成功，不会因为缺少字节规则而被误拒。

不得把故障伪装成命中，也不得把故障当作通过。

## 覆盖能力（如实描述）

通过只表示：

> 在该规则版本、支持格式及检查字节范围内未发现命中。

测试规则包只能证明扫描链路可执行，**不能**证明具备生产恶意软件检出能力。若还没有经审核的生产规则集，不得把测试规则当作生产防护发布。

### 当前支持

- 已知文件 SHA-256 精确命中
- 适用 MIME 范围内的字节特征匹配（处理分块边界）
- 本地规则包版本与 SHA-256 完整性校验
- 规则包原始字节上限、扫描字节、规则数量、特征长度上限
- 上下文取消

### 规则包加载上限

| 常量 | 取值 | 单位 | 作用 |
| --- | --- | --- | --- |
| `MaxRulePackBytes` | `1 << 20`（1048576） | 字节 | 规则包原始内容在摘要校验与 JSON 解析前的硬上限 |

依据：规则包是已审核的本地配置，不是上传文件。先限长再验摘要/解析，避免异常或被替换的超大文件在验签前占满内存。该上限与单次上传内容扫描的 `MaxScanBytes` 相互独立；规则条数与特征长度仍在解析后另行约束。

文件入口最多读取“上限 + 1 字节”判断超限；字节入口先检查 `len(raw)`。恰好等于上限且摘要合法时可加载；超过一字节即使摘要正确也按 `ErrInvalidConfig` 拒绝。

### 当前不支持

- 联网拉取规则或回传样本
- 执行上传文件、调用 shell、无界解压
- 启发式行为分析、沙箱、宏/脚本仿真
- 替代 ClamAV 或其他专业引擎的完整病毒库能力

ClamAV 适配器仍然保留，可与离线引擎并存注册。

## 生产装配

```go
scanner, err := offline.NewFromFile("/etc/uploadkit/rules.prod.json", expectedSHA256)
if err != nil {
	return err
}

policy, err := uploadkit.NewPolicy(uploadkit.PolicyOptions{
	RequireMalwareScanner: true,
	// ... 业务 MIME 与大小限制
})

uploader, err := uploadkit.New(
	store,
	uploadkit.WithDefaultPolicy(policy),
	uploadkit.WithScanner(scanner),
)
```

要点：

1. 启动时一次性装配；必需引擎未配置或规则无效时初始化失败。
2. 普通上传继续使用 `Upload` / `UploadRequest`，不新增平行入口。
3. 实例默认策略启用 `RequireMalwareScanner` 后，即使请求覆盖了其他 Policy 字段，也不能关闭扫描。
4. 一次上传只使用一个不可变规则版本。

## 规则包格式

```json
{
  "version": "2026.11.20-1",
  "max_scan_bytes": 10485760,
  "rules": [
    {
      "id": "hash.example",
      "kind": "sha256",
      "sha256": "64位小写十六进制",
      "mime": ["application/pdf"],
      "threat": "Example.Hash"
    },
    {
      "id": "bytes.example",
      "kind": "bytes",
      "pattern": "十六进制字节特征",
      "mime": ["text/plain"],
      "threat": "Example.Bytes"
    }
  ]
}
```

规则要求：

- 稳定 `id`、明确 `kind`、可测试样本、清晰 `threat`
- 不把文件名、扩展名或几个脚本关键词当成杀毒结论
- `mime` 为空或包含 `*/*` 时对引擎支持的输入生效

## 规则审核、更新与回滚

1. **审核**：规则由安全负责人审核后入库；每条规则保留 ID、适用范围、样本哈希和变更说明。
2. **发布**：将规则包放到主机本地路径，计算文件 SHA-256，更新部署配置中的 `expectedSHA256` 与版本号。
3. **生效**：重启或重建 `Uploader`；运行中不会热加载，也不会联网拉取。
4. **回滚**：保留上一版本规则包文件与摘要；把配置改回旧路径和旧摘要后重启即可。
5. **禁止**：运行时下载规则、自动上传样本、或在摘要校验失败时继续“降级放行”。

## 示例

- 普通上传与追加检查：[`examples/with_inspectors`](../examples/with_inspectors)
- 离线扫描装配与无害命中：[`examples/offline_scan`](../examples/offline_scan)
