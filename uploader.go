package uploadkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultContentDisposition = "attachment" // defaultContentDisposition 默认下载展示方式
	maxMetadataEntries        = 64           // maxMetadataEntries 单对象元数据数量上限
	maxMetadataLength         = 1024         // maxMetadataLength 单个元数据键值长度上限
)

// Uploader 组织来源隔离、安全检查和对象存储写入。
// Uploader 初始化完成后只读，可以被多个 goroutine 并发复用。
type Uploader struct {
	store                 Store            // store 统一对象存储适配器
	tempDir               string           // tempDir 隔离文件目录
	defaultPolicy         Policy           // defaultPolicy 未指定请求策略时使用的默认策略
	keyGenerator          KeyGenerator     // keyGenerator 对象键生成器
	scanners              []Scanner        // scanners 病毒扫描器只读副本
	inspectors            []Inspector      // inspectors 自定义检查器只读副本
	cleanupHandler        ErrorHandler     // cleanupHandler 临时文件清理错误处理器
	semaphore             chan struct{}    // semaphore 限制隔离文件并发数量
	maxConcurrency        int              // maxConcurrency 保存并发上限
	requireMalwareScanner bool             // requireMalwareScanner 实例级强制扫描，请求策略不能关闭
	now                   func() time.Time // now 提供当前时间
}

// New 创建并发安全的上传器。
// @param store Store 对象存储适配器
// @param options ...Option 初始化选项
// @return result *Uploader 上传器
// @return err error 配置错误
func New(store Store, options ...Option) (result *Uploader, err error) {
	// 对象存储适配器是上传器的必需依赖。
	if store == nil {
		return nil, ErrNilStore
	}
	// 从安全默认值开始构建上传器配置。
	config := defaultUploaderConfig()
	// 按调用顺序应用每一个初始化选项。
	for _, option := range options {
		// 空选项无法修改配置，直接返回参数错误。
		if option == nil {
			return nil, fmt.Errorf("%w: option is nil", ErrInvalidConfig)
		}
		// 选项校验失败时停止构建上传器。
		if err = option(&config); err != nil {
			return nil, err
		}
	}
	// 显式隔离目录必须在初始化时已经存在。
	if config.tempDir != "" {
		// 读取目录信息，避免将配置错误延迟到第一次上传。
		info, statErr := os.Stat(config.tempDir)
		if statErr != nil {
			return nil, fmt.Errorf("inspect upload temp directory: %w", statErr)
		}
		// 普通文件不能作为隔离目录。
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: temp directory is not a directory", ErrInvalidConfig)
		}
	}
	// 实例默认策略要求扫描时，必需扫描器必须在初始化阶段完成装配。
	if config.defaultPolicy.requireMalwareScanner && len(config.scanners) == 0 {
		return nil, ErrScannerRequired
	}
	// 复制可变切片，并创建固定容量的并发信号量。
	return &Uploader{
		store:                 store,
		tempDir:               config.tempDir,
		defaultPolicy:         config.defaultPolicy,
		keyGenerator:          config.keyGenerator,
		scanners:              append([]Scanner(nil), config.scanners...),
		inspectors:            append([]Inspector(nil), config.inspectors...),
		cleanupHandler:        config.cleanupHandler,
		semaphore:             make(chan struct{}, config.maxConcurrency),
		maxConcurrency:        config.maxConcurrency,
		requireMalwareScanner: config.defaultPolicy.requireMalwareScanner,
		now:                   config.now,
	}, nil
}

// Upload 使用默认策略上传一个文件来源。
// @param ctx context.Context 调用上下文
// @param source Source 文件数据来源
// @return result Result 上传结果
// @return err error 来源、检查或存储错误
func (u *Uploader) Upload(ctx context.Context, source Source) (result Result, err error) {
	// 简单入口只组装来源，其余行为统一复用高级请求入口。
	return u.UploadRequest(ctx, Request{Source: source})
}

// UploadRequest 按请求参数执行一个文件的完整上传流程。
// @param ctx context.Context 调用上下文
// @param request Request 上传请求
// @return result Result 上传结果
// @return err error 来源、策略、检查或存储错误
func (u *Uploader) UploadRequest(ctx context.Context, request Request) (result Result, err error) {
	// 上传器或存储为空时不能执行持久化。
	if u == nil || u.store == nil {
		return Result{}, ErrNilStore
	}
	// 所有上传操作统一要求调用方提供上下文。
	if ctx == nil {
		return Result{}, ErrNilContext
	}
	// 每次上传都必须提供明确的数据来源。
	if request.Source == nil {
		return Result{}, ErrNilSource
	}
	// 请求没有指定策略时使用 Uploader 初始化时保存的默认策略。
	policy := request.Policy
	if !policy.valid() {
		policy = u.defaultPolicy
	}
	// Uploader 默认策略异常时不能继续读取文件。
	if !policy.valid() {
		return Result{}, ErrInvalidPolicy
	}
	// 固定对象键已经包含完整命名空间，不能再同时指定目录前缀。
	if request.ObjectKey != "" && strings.TrimSpace(request.Prefix) != "" {
		return Result{}, fmt.Errorf("%w: ObjectKey and Prefix cannot be used together", ErrInvalidConfig)
	}
	// 实例级强制扫描不能被请求策略关闭；请求策略也可额外要求扫描。
	requireScan := u.requireMalwareScanner || policy.requireMalwareScanner
	// 任一强制扫描开关启用时至少需要一个已注册扫描器。
	if requireScan && len(u.scanners) == 0 {
		return Result{}, ErrScannerRequired
	}
	// 复制并校验对象元数据，避免调用方在上传期间修改映射。
	metadata, err := normalizeMetadata(request.Metadata)
	// 元数据非法时不创建临时文件。
	if err != nil {
		return Result{}, err
	}
	// 规范并校验对象的 Content-Disposition。
	disposition, err := normalizeContentDisposition(request.ContentDisposition)
	// 响应头内容非法时不进入上传流程。
	if err != nil {
		return Result{}, err
	}
	// 获取一个隔离文件并发名额，限制临时磁盘压力。
	if err = u.acquire(ctx); err != nil {
		return Result{}, err
	}
	// 上传结束后归还并发名额。
	defer u.release()

	// 将来源完整写入有界隔离文件并计算可信文件事实。
	staged, err := stageSource(ctx, request.Source, policy, u.tempDir)
	// 隔离失败时不执行任何存储操作。
	if err != nil {
		return Result{}, err
	}
	// 无论后续成功或失败都关闭并删除隔离文件。
	defer func() {
		// 清理失败不改变已经确定的上传结果，只交给调用方记录。
		if closeErr := staged.close(); closeErr != nil && u.cleanupHandler != nil {
			u.cleanupHandler(closeErr)
		}
	}()
	// 校验真实 MIME、扩展名和策略开关。
	if err = policy.validateType(staged.originalName, staged.mimeType); err != nil {
		return Result{}, err
	}
	// 执行图片、SVG 和 ZIP 的内置结构检查。
	if err = inspectBuiltIn(ctx, staged, policy); err != nil {
		return Result{}, err
	}
	// 执行调用方按顺序注册的自定义检查器。
	if err = u.runInspectors(ctx, staged, request.inspectors); err != nil {
		return Result{}, err
	}
	// 执行调用方按顺序注册的恶意内容扫描器。
	if err = u.runScanners(ctx, staged); err != nil {
		return Result{}, err
	}

	// 固定对象键优先使用调用方显式值。
	objectKey := request.ObjectKey
	// 未指定固定键时使用上传器的安全对象键生成器。
	if objectKey == "" {
		// 只向生成器提供隔离阶段确认的文件事实。
		objectKey, err = u.keyGenerator(KeyInput{
			Prefix:         request.Prefix,
			OriginalName:   staged.originalName,
			MIMEType:       staged.mimeType,
			Size:           staged.size,
			ChecksumSHA256: staged.checksum,
			CreatedAt:      u.now().UTC(),
		})
		// 对象键生成失败时不调用存储适配器。
		if err != nil {
			return Result{}, err
		}
	}
	// 固定键和生成键都必须经过相同结构校验。
	if err = ValidateObjectKey(objectKey); err != nil {
		return Result{}, err
	}
	// 存储前将隔离文件恢复到内容起点。
	if err = staged.seekStart(); err != nil {
		return Result{}, err
	}
	// 将已经通过检查的文件事实和读取流交给存储适配器。
	stored, err := u.store.Put(ctx, PutObject{
		Key:                objectKey,
		Body:               staged.file,
		Size:               staged.size,
		ContentType:        staged.mimeType,
		ContentDisposition: disposition,
		ChecksumSHA256:     staged.checksum,
		Metadata:           metadata,
	})
	// 存储错误由适配器负责清理自身未完成写入。
	if err != nil {
		return Result{}, err
	}
	// 返回真实文件事实和存储服务生成的对象信息。
	return Result{
		OriginalName:   staged.originalName,
		ObjectKey:      objectKey,
		MIMEType:       staged.mimeType,
		Size:           staged.size,
		ChecksumSHA256: staged.checksum,
		ETag:           stored.ETag,
		VersionID:      stored.VersionID,
	}, nil
}

// Delete 删除指定对象。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @return err error 参数或存储错误
func (u *Uploader) Delete(ctx context.Context, objectKey string) error {
	// 上传器或存储为空时不能执行删除。
	if u == nil || u.store == nil {
		return ErrNilStore
	}
	// 删除操作统一要求调用方提供上下文。
	if ctx == nil {
		return ErrNilContext
	}
	// 删除前校验对象键，避免路径语义进入适配器。
	if err := ValidateObjectKey(objectKey); err != nil {
		return err
	}
	// 将删除动作交给当前存储适配器。
	return u.store.Delete(ctx, objectKey)
}

// SignedURL 创建对象临时访问地址。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @param expires time.Duration 有效时间
// @return result string 临时访问地址
// @return err error 参数、不支持或存储错误
func (u *Uploader) SignedURL(ctx context.Context, objectKey string, expires time.Duration) (result string, err error) {
	// 上传器或存储为空时不能创建签名地址。
	if u == nil || u.store == nil {
		return "", ErrNilStore
	}
	// 签名操作统一要求调用方提供上下文。
	if ctx == nil {
		return "", ErrNilContext
	}
	// 签名前校验对象键结构。
	if err = ValidateObjectKey(objectKey); err != nil {
		return "", err
	}
	// 有效期必须为正数。
	if expires <= 0 {
		return "", fmt.Errorf("%w: signed URL expiry is invalid", ErrInvalidConfig)
	}
	// 通过可选能力接口判断当前存储是否支持签名地址。
	signer, supported := u.store.(URLSigner)
	// 不支持时返回明确的能力错误。
	if !supported {
		return "", ErrSignedURLUnsupported
	}
	// 由存储适配器生成符合厂商协议的临时地址。
	return signer.SignedURL(ctx, objectKey, expires)
}

// Ping 主动检查对象存储是否可用。
// @param ctx context.Context 调用上下文
// @return err error 不支持或存储错误
func (u *Uploader) Ping(ctx context.Context) error {
	// 上传器或存储为空时不能执行健康检查。
	if u == nil || u.store == nil {
		return ErrNilStore
	}
	// 健康检查统一要求调用方提供上下文。
	if ctx == nil {
		return ErrNilContext
	}
	// 通过可选能力接口判断当前存储是否支持主动检查。
	checker, supported := u.store.(HealthChecker)
	// 不支持时返回明确的能力错误。
	if !supported {
		return ErrHealthCheckUnsupported
	}
	// 由存储适配器检查端点、凭证和存储桶。
	return checker.Ping(ctx)
}

// UploadMany 使用 Uploader 默认策略批量上传多个来源。
// @param ctx context.Context 调用上下文
// @param sources []Source 文件来源列表
// @return result BatchResult 有序批量结果
// @return err error 批量参数、上下文或批量部分失败错误
func (u *Uploader) UploadMany(ctx context.Context, sources []Source) (result BatchResult, err error) {
	// 上传器或存储为空时不能读取默认策略或执行批量上传。
	if u == nil || u.store == nil {
		return BatchResult{}, ErrNilStore
	}
	// 默认批量入口复用 Uploader 初始化时保存的策略。
	return u.UploadManyWithPolicy(ctx, sources, u.defaultPolicy)
}

// UploadManyWithPolicy 使用指定策略批量上传多个来源。
// @param ctx context.Context 调用上下文
// @param sources []Source 文件来源列表
// @param policy Policy 上传策略
// @return result BatchResult 有序批量结果
// @return err error 批量参数、上下文或批量部分失败错误
func (u *Uploader) UploadManyWithPolicy(ctx context.Context, sources []Source, policy Policy) (result BatchResult, err error) {
	// 只接受由 NewPolicy 构建并包含批量上限的策略。
	if !policy.valid() || policy.maxFiles <= 0 {
		return BatchResult{}, ErrInvalidPolicy
	}
	// 批量来源数量不能超过策略上限。
	if len(sources) > policy.maxFiles {
		return BatchResult{}, fmt.Errorf("%w: count=%d max=%d", ErrTooManyFiles, len(sources), policy.maxFiles)
	}
	// 将同一策略的来源转换为统一批量请求。
	requests := make([]Request, len(sources))
	// 保持来源输入顺序构建请求。
	for index, source := range sources {
		requests[index] = Request{Source: source, Policy: policy}
	}
	// 复用通用批量上传执行器。
	return u.UploadBatch(ctx, requests)
}

// UploadBatch 并发执行不同策略的上传请求并保持输入顺序。
// @param ctx context.Context 调用上下文
// @param requests []Request 上传请求列表
// @return result BatchResult 有序批量结果
// @return err error 整体参数、上下文或批量部分失败错误
func (u *Uploader) UploadBatch(ctx context.Context, requests []Request) (result BatchResult, err error) {
	// 上传器或存储为空时不能执行批量上传。
	if u == nil || u.store == nil {
		return BatchResult{}, ErrNilStore
	}
	// 批量操作统一要求调用方提供上下文。
	if ctx == nil {
		return BatchResult{}, ErrNilContext
	}
	// 空批次返回已初始化的空结果。
	if len(requests) == 0 {
		return BatchResult{Items: []BatchItem{}}, nil
	}
	// 每个请求的策略都必须允许当前批次大小。
	for _, request := range requests {
		// 未指定请求策略时使用 Uploader 默认策略。
		policy := request.Policy
		if !policy.valid() {
			policy = u.defaultPolicy
		}
		// Uploader 和请求策略均无效时拒绝整个批次。
		if !policy.valid() || policy.maxFiles <= 0 {
			return BatchResult{}, ErrInvalidPolicy
		}
		// 任一策略的批量上限不足时拒绝整个批次。
		if len(requests) > policy.maxFiles {
			return BatchResult{}, fmt.Errorf("%w: count=%d max=%d", ErrTooManyFiles, len(requests), policy.maxFiles)
		}
	}

	// 预分配固定长度结果，工作协程按独立下标写入。
	result.Items = make([]BatchItem, len(requests))
	// 提前写入每个结果下标，保证取消时未调度项目也能准确定位。
	for index := range result.Items {
		result.Items[index].Index = index
	}
	// 工作协程数量不超过上传器并发上限和请求数量。
	workerCount := min(u.maxConcurrency, len(requests))
	// jobs 只传递待处理请求下标。
	jobs := make(chan int)
	// wait 等待全部工作协程退出。
	var wait sync.WaitGroup
	// 预先登记工作协程数量。
	wait.Add(workerCount)
	// 创建固定数量的批量上传工作协程。
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			// 当前工作协程退出时减少等待计数。
			defer wait.Done()
			// 持续消费任务下标直到通道关闭。
			for index := range jobs {
				// 复用单文件完整上传流程。
				uploadResult, uploadErr := u.UploadRequest(ctx, requests[index])
				// 每个下标只由一个协程写入，不需要额外锁。
				result.Items[index] = BatchItem{Index: index, Result: uploadResult, Err: uploadErr}
			}
		}()
	}
	// dispatchErr 保存投递阶段出现的上下文错误。
	var dispatchErr error
	// 按输入顺序投递每个请求下标。
dispatchLoop:
	for index := range requests {
		// 已经取消的上下文不再尝试投递新的上传任务。
		if contextErr := ctx.Err(); contextErr != nil {
			dispatchErr = contextErr
			for pendingIndex := index; pendingIndex < len(result.Items); pendingIndex++ {
				result.Items[pendingIndex].Err = dispatchErr
			}
			break dispatchLoop
		}
		select {
		// 工作协程可接收时发送当前下标。
		case jobs <- index:
		// 上下文取消时停止投递并等待已接收任务结束。
		case <-ctx.Done():
			// 保存取消错误，并为尚未调度的项目写入明确失败原因。
			dispatchErr = ctx.Err()
			for pendingIndex := index; pendingIndex < len(result.Items); pendingIndex++ {
				result.Items[pendingIndex].Err = dispatchErr
			}
			// 停止继续投递，已经接收的任务仍由工作协程正常收尾。
			break dispatchLoop
		}
	}
	// 所有下标投递完成后关闭任务通道。
	close(jobs)
	// 等待工作协程完成当前批次。
	wait.Wait()
	// batchContextErr 保留工作协程返回的第一个上下文错误。
	var batchContextErr error
	// 根据每项错误汇总成功和失败数量。
	for _, item := range result.Items {
		// 带错误的项目计入失败数量。
		if item.Err != nil {
			result.Failed++
			// 工作协程返回上下文错误时保留整体取消语义。
			if batchContextErr == nil && (errors.Is(item.Err, context.Canceled) || errors.Is(item.Err, context.DeadlineExceeded)) {
				batchContextErr = item.Err
			}
			continue
		}
		// 无错误的项目计入成功数量。
		result.Succeeded++
	}
	// 投递阶段取消时返回完整的有序结果和原始上下文错误。
	if dispatchErr != nil {
		return result, dispatchErr
	}
	// 工作协程因上下文结束失败时返回当前上下文状态。
	if batchContextErr != nil {
		// 调用上下文已结束时优先返回它的标准错误。
		if contextErr := ctx.Err(); contextErr != nil {
			return result, contextErr
		}
		// 底层返回独立上下文错误时不能将顶层错误误报为空。
		return result, batchContextErr
	}
	// 单项失败必须通过顶层错误显式反馈，避免调用方误判整批成功。
	if result.Failed > 0 {
		return result, fmt.Errorf("%w: failed=%d succeeded=%d", ErrBatchFailed, result.Failed, result.Succeeded)
	}
	// 返回保持输入顺序的完整批量结果。
	return result, nil
}

// runInspectors 按顺序执行实例检查器和本次请求追加的检查器。
// @param ctx context.Context 调用上下文
// @param staged *stagedFile 隔离文件
// @param requestInspectors []Inspector 请求级追加检查器
// @return err error 检查错误
func (u *Uploader) runInspectors(ctx context.Context, staged *stagedFile, requestInspectors []Inspector) error {
	// 先执行实例级检查器，再执行请求级追加检查器，两类都不能被跳过。
	inspectors := make([]Inspector, 0, len(u.inspectors)+len(requestInspectors))
	// 复制实例检查器引用，保持注册顺序。
	inspectors = append(inspectors, u.inspectors...)
	// 追加本次请求专属检查器，不修改 Uploader 共享状态。
	inspectors = append(inspectors, requestInspectors...)
	// 按顺序执行每一个内容检查器。
	for _, inspector := range inspectors {
		// 每个检查器都获得独立且不可写的完整内容视图。
		content, err := staged.contentReader()
		if err != nil {
			return err
		}
		// 任一检查器拒绝文件时立即终止上传。
		if err = inspector.Inspect(ctx, staged.info(), content); err != nil {
			return err
		}
	}
	// 全部检查完成后为下一阶段恢复文件偏移。
	return staged.seekStart()
}

// runScanners 执行所有病毒扫描器，任意扫描异常均停止上传。
// @param ctx context.Context 调用上下文
// @param staged *stagedFile 隔离文件
// @return err error 扫描错误或威胁结果
func (u *Uploader) runScanners(ctx context.Context, staged *stagedFile) error {
	// 按注册顺序执行每一个恶意内容扫描器。
	for _, scanner := range u.scanners {
		// 每个扫描器都获得独立且不可写的完整内容视图。
		content, err := staged.contentReader()
		// 无法读取暂存内容时按扫描未完成处理，不能伪装成未命中。
		if err != nil {
			return fmt.Errorf("%w: %v", ErrScanIncomplete, err)
		}
		// 执行扫描并获取明确结果。
		result, err := scanner.Scan(ctx, staged.info(), content)
		// 扫描器异常时按失败关闭，并与威胁命中区分开。
		if err != nil {
			// 上下文取消或超时保留原始语义，便于上层重试或中止。
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// 其他扫描故障统一包装为未完成，避免被误判为通过或命中。
			if errors.Is(err, ErrScanIncomplete) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrScanIncomplete, err)
		}
		// 未确认安全或返回威胁名称时拒绝文件。
		if !result.Clean || strings.TrimSpace(result.Threat) != "" {
			return fmt.Errorf("%w: %s", ErrThreatDetected, strings.TrimSpace(result.Threat))
		}
	}
	// 全部扫描完成后为存储阶段恢复文件偏移。
	return staged.seekStart()
}

// acquire 获取一个隔离上传并发名额。
// @param ctx context.Context 调用上下文
// @return err error 上下文错误
func (u *Uploader) acquire(ctx context.Context) error {
	// 并发名额可用时占用一个信号量槽位。
	select {
	case u.semaphore <- struct{}{}:
		return nil
	// 等待期间上下文取消时终止上传。
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release 释放一个隔离上传并发名额。
func (u *Uploader) release() {
	// 读取一个信号量槽位，归还并发名额。
	<-u.semaphore
}

// normalizeMetadata 复制并校验对象元数据。
// @param metadata map[string]string 元数据
// @return result map[string]string 安全副本
// @return err error 非法键值错误
func normalizeMetadata(metadata map[string]string) (result map[string]string, err error) {
	// 空元数据不需要分配返回映射。
	if len(metadata) == 0 {
		return nil, nil
	}
	// 限制元数据数量，避免协议头和内存被滥用。
	if len(metadata) > maxMetadataEntries {
		return nil, fmt.Errorf("%w: too many metadata entries", ErrInvalidConfig)
	}
	// 创建独立映射，隔离调用方后续修改。
	result = make(map[string]string, len(metadata))
	// 逐项规范并校验元数据键值。
	for key, value := range metadata {
		// 元数据键统一使用小写并清除两端空白。
		key = strings.ToLower(strings.TrimSpace(key))
		// 键不能为空，键值长度均不能超过单项上限。
		if key == "" || len(key) > maxMetadataLength || len(value) > maxMetadataLength {
			return nil, fmt.Errorf("%w: invalid metadata", ErrInvalidConfig)
		}
		// 键只允许小写 ASCII 字母、数字和连字符。
		for _, character := range key {
			// 发现范围外字符时拒绝整组元数据。
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return nil, fmt.Errorf("%w: invalid metadata key", ErrInvalidConfig)
			}
		}
		// 值不允许包含控制字符。
		for _, character := range value {
			// 控制字符可能改变下游协议头语义。
			if character < 0x20 || character == 0x7f {
				return nil, fmt.Errorf("%w: invalid metadata value", ErrInvalidConfig)
			}
		}
		// 规范化后重复的键不能静默覆盖。
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("%w: duplicate metadata key", ErrInvalidConfig)
		}
		// 保存完成校验的元数据键值。
		result[key] = value
	}
	// 返回与调用方映射隔离的元数据副本。
	return result, nil
}

// normalizeContentDisposition 校验对象展示方式不能注入响应头。
// @param value string Content-Disposition 值
// @return result string 规范值
// @return err error 非法值错误
func normalizeContentDisposition(value string) (result string, err error) {
	// 清除展示方式两端空白。
	value = strings.TrimSpace(value)
	// 空值使用下载型 attachment 默认值。
	if value == "" {
		return defaultContentDisposition, nil
	}
	// 限制长度并拒绝 CRLF 响应头注入。
	if len(value) > maxMetadataLength || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%w: invalid content disposition", ErrInvalidConfig)
	}
	// 返回经过校验的展示方式。
	return value, nil
}
