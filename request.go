package uploadkit

// Request 描述一次文件上传。
type Request struct {
	inspectors         []Inspector       // inspectors 仅追加于当前请求，不覆盖实例检查器
	Source             Source            // Source 文件数据来源
	Policy             Policy            // Policy 可选的本次上传策略，零值使用 Uploader 默认策略
	ObjectKey          string            // ObjectKey 可选的本次上传固定对象键
	Prefix             string            // Prefix 调用方确认可信的对象目录
	ContentDisposition string            // ContentDisposition 对象展示方式，默认 attachment
	Metadata           map[string]string // Metadata 对象存储元数据
}

// WithInspectors 返回追加了本次检查器的请求副本，保留实例级检查。
// @description 追加不会修改原请求，也不会替换 Uploader 注册的实例检查器；插件只能由可信服务端代码提供
// @param extra ...Inspector 本次请求追加的内容检查器
// @return result Request 带有追加检查器的请求副本
func (r Request) WithInspectors(extra ...Inspector) Request {
	// 空追加列表仍返回独立副本，避免调用方误以为会共享底层切片。
	copied := append([]Inspector(nil), r.inspectors...)
	// 按调用顺序追加本次请求专属检查器。
	r.inspectors = append(copied, extra...)
	// 值接收者保证调用方持有的原请求保持不变。
	return r
}

// Result 描述一次成功上传。
type Result struct {
	OriginalName   string // OriginalName 清理后的原始文件名
	ObjectKey      string // ObjectKey 最终对象键
	MIMEType       string // MIMEType 真实文件类型
	Size           int64  // Size 实际文件大小
	ChecksumSHA256 string // ChecksumSHA256 十六进制 SHA-256
	ETag           string // ETag 存储服务对象标识
	VersionID      string // VersionID 对象版本号
}

// BatchItem 描述批量上传中一个文件的执行结果。
type BatchItem struct {
	Index  int    // Index 请求下标
	Result Result // Result 成功结果
	Err    error  // Err 独立失败原因
}

// BatchResult 描述保持请求顺序的批量上传结果。
type BatchResult struct {
	Items     []BatchItem // Items 每个请求的执行结果
	Succeeded int         // Succeeded 成功数量
	Failed    int         // Failed 失败数量
}
