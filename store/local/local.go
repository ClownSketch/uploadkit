// Package local 实现受目录边界保护的本地文件系统存储适配器。
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ClownSketch/uploadkit"
)

const (
	defaultDirectoryMode os.FileMode = 0o750    // defaultDirectoryMode 默认目录权限
	defaultFileMode      os.FileMode = 0o640    // defaultFileMode 默认文件权限
	copyBufferSize                   = 64 << 10 // copyBufferSize 本地对象写入缓冲区大小
)

// Config 定义本地存储初始化参数。
type Config struct {
	Root           string                 // Root 对象存储根目录
	DirectoryMode  os.FileMode            // DirectoryMode 新建目录权限
	FileMode       os.FileMode            // FileMode 新建文件权限
	AllowOverwrite bool                   // AllowOverwrite 是否允许覆盖同名对象
	ErrorHandler   uploadkit.ErrorHandler // ErrorHandler 提交后清理异常处理器
}

// Store 将对象持久化到受控本地目录。
type Store struct {
	root           string                 // root 已解析的绝对根目录
	directoryMode  os.FileMode            // directoryMode 新建目录权限
	fileMode       os.FileMode            // fileMode 新建文件权限
	allowOverwrite bool                   // allowOverwrite 是否允许覆盖
	errorHandler   uploadkit.ErrorHandler // errorHandler 提交后清理异常处理器
}

// New 创建本地文件系统存储适配器。
// @param config Config 本地存储配置
// @return result *Store 本地存储适配器
// @return err error 配置或目录错误
func New(config Config) (result *Store, err error) {
	// 清除根目录两端空白。
	root := strings.TrimSpace(config.Root)
	// 本地存储必须配置明确根目录。
	if root == "" {
		return nil, fmt.Errorf("%w: local root is empty", uploadkit.ErrInvalidConfig)
	}
	// 转换为绝对路径，避免工作目录变化影响对象位置。
	absoluteRoot, err := filepath.Abs(root)
	// 路径解析失败时终止初始化。
	if err != nil {
		return nil, fmt.Errorf("resolve local store root: %w", err)
	}
	// 读取调用方配置的目录权限。
	directoryMode := config.DirectoryMode
	// 零值使用最小化的默认目录权限。
	if directoryMode == 0 {
		directoryMode = defaultDirectoryMode
	}
	// 读取调用方配置的文件权限。
	fileMode := config.FileMode
	// 零值使用最小化的默认文件权限。
	if fileMode == 0 {
		fileMode = defaultFileMode
	}
	// 权限位为空会创建不可访问对象，初始化时直接拒绝。
	if directoryMode.Perm() == 0 || fileMode.Perm() == 0 {
		return nil, fmt.Errorf("%w: local file mode is empty", uploadkit.ErrInvalidConfig)
	}
	// 创建存储根目录及缺失的父目录。
	if err = os.MkdirAll(absoluteRoot, directoryMode.Perm()); err != nil {
		return nil, fmt.Errorf("create local store root: %w", err)
	}
	// 解析根目录本身的符号链接，固定真实边界。
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	// 根目录无法解析时不能提供可靠路径边界。
	if err != nil {
		return nil, fmt.Errorf("resolve local store root symlink: %w", err)
	}
	// 保存清理后的不可变配置，供并发请求复用。
	return &Store{
		root:           filepath.Clean(resolvedRoot),
		directoryMode:  directoryMode.Perm(),
		fileMode:       fileMode.Perm(),
		allowOverwrite: config.AllowOverwrite,
		errorHandler:   config.ErrorHandler,
	}, nil
}

// Put 保存已经通过 uploadkit 检查的对象。
// @param ctx context.Context 调用上下文
// @param object uploadkit.PutObject 待保存对象
// @return result uploadkit.StoredObject 存储结果
// @return err error 路径、读取或写入错误
func (s *Store) Put(ctx context.Context, object uploadkit.PutObject) (result uploadkit.StoredObject, err error) {
	// 空存储对象无法执行本地写入。
	if s == nil {
		return uploadkit.StoredObject{}, uploadkit.ErrNilStore
	}
	// 本地写入统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.StoredObject{}, uploadkit.ErrNilContext
	}
	// 写入文件系统前执行所有存储适配器共享的对象参数校验。
	if err = uploadkit.ValidatePutObject(object); err != nil {
		return uploadkit.StoredObject{}, err
	}
	// 将对象键解析为根目录内的绝对目标路径。
	targetPath, err := s.objectPath(object.Key)
	// 对象键非法时不创建任何目录。
	if err != nil {
		return uploadkit.StoredObject{}, err
	}
	// 逐级创建并校验目标目录，避免沿符号链接在根目录外产生副作用。
	if err = s.ensureObjectDirectory(filepath.Dir(targetPath)); err != nil {
		return uploadkit.StoredObject{}, err
	}
	// 从对象内容起点开始写入临时文件。
	if _, err = object.Body.Seek(0, io.SeekStart); err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("rewind local object body: %w", err)
	}
	// 在目标目录创建临时文件，确保最终提交位于同一文件系统。
	tempFile, err := os.CreateTemp(filepath.Dir(targetPath), ".uploadkit-*")
	// 临时文件创建失败时目标对象保持不变。
	if err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("create local object temp file: %w", err)
	}
	// 保存临时路径供提交或失败清理使用。
	tempPath := tempFile.Name()
	// tempClosed 标记临时文件是否已经主动关闭。
	tempClosed := false
	// committed 标记临时文件是否已经转为正式对象。
	committed := false
	// 未提交成功时关闭并删除半成品临时文件。
	defer func() {
		if !committed {
			// 未关闭的临时文件先释放文件描述符。
			var closeErr error
			if !tempClosed {
				closeErr = tempFile.Close()
			}
			// 删除没有提交的临时文件。
			removeErr := os.Remove(tempPath)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
			// 清理异常进入原始错误链，确保调用方能够观测临时文件泄漏。
			if cleanupErr := errors.Join(closeErr, removeErr); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup local object temp file: %w", cleanupErr))
			}
		}
	}()
	// 在写入前设置目标文件权限。
	if err = tempFile.Chmod(s.fileMode); err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("set local object mode: %w", err)
	}
	// 流式写入对象内容，并在复制过程中响应取消信号。
	written, err := copyWithContext(ctx, tempFile, object.Body)
	// 写入失败时保留临时文件清理流程。
	if err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("write local object: %w", err)
	}
	// 实际写入大小必须与核心层确认的大小一致。
	if written != object.Size {
		return uploadkit.StoredObject{}, fmt.Errorf("write local object: size mismatch actual=%d expected=%d", written, object.Size)
	}
	// 提交前将文件内容和元数据刷新到稳定存储。
	if err = tempFile.Sync(); err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("sync local object: %w", err)
	}
	// 提交前关闭文件，确保所有写入状态返回到操作系统。
	if err = tempFile.Close(); err != nil {
		return uploadkit.StoredObject{}, fmt.Errorf("close local object: %w", err)
	}
	// 记录文件已经关闭，失败清理不再重复关闭。
	tempClosed = true
	// 允许覆盖时使用原子重命名替换目标对象。
	if s.allowOverwrite {
		err = os.Rename(tempPath, targetPath)
	} else {
		// 禁止覆盖时使用硬链接获得原子仅创建语义。
		err = os.Link(tempPath, targetPath)
	}
	// 处理对象提交失败。
	if err != nil {
		// 禁止覆盖模式下目标已存在时返回统一错误。
		if !s.allowOverwrite && errors.Is(err, os.ErrExist) {
			return uploadkit.StoredObject{}, uploadkit.ErrObjectExists
		}
		// 其他提交错误保留底层原因。
		return uploadkit.StoredObject{}, fmt.Errorf("commit local object: %w", err)
	}
	// 标记对象已经完成原子提交。
	committed = true
	// 硬链接提交后删除不再需要的临时目录项。
	if !s.allowOverwrite {
		// 删除失败不影响已经持久化的正式对象。
		if err = os.Remove(tempPath); err != nil {
			// 配置错误处理器时交由调用方记录清理异常。
			if s.errorHandler != nil {
				s.errorHandler(fmt.Errorf("remove committed local temp file: %w", err))
			}
		}
	}
	// 返回本地对象的内容哈希。
	return uploadkit.StoredObject{
		ETag: object.ChecksumSHA256,
	}, nil
}

// Delete 删除本地对象；对象不存在视为成功。
// @param ctx context.Context 调用上下文
// @param objectKey string 对象键
// @return err error 路径或删除错误
func (s *Store) Delete(ctx context.Context, objectKey string) error {
	// 空存储对象无法执行删除。
	if s == nil {
		return uploadkit.ErrNilStore
	}
	// 删除操作统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ErrNilContext
	}
	// 已取消的请求不再访问文件系统。
	if err := ctx.Err(); err != nil {
		return err
	}
	// 将对象键解析为根目录内的目标路径。
	targetPath, err := s.objectPath(objectKey)
	// 对象键非法时不执行删除。
	if err != nil {
		return err
	}
	// 删除前检查已存在的目录链，防止中间符号链提供根目录外路径。
	objectDirectory := filepath.Dir(targetPath)
	if _, statErr := os.Lstat(objectDirectory); statErr != nil {
		// 目标目录不存在时，对象必然不存在，保持删除幂等。
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect local object directory: %w", statErr)
	}
	// 复用写入阶段的逐级目录校验，已存在目录不会产生新节点。
	if err = s.ensureObjectDirectory(objectDirectory); err != nil {
		return err
	}
	// 删除正式对象，对象不存在时保持幂等成功。
	if err = os.Remove(targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete local object: %w", err)
	}
	// 对象删除完成或原本不存在。
	return nil
}

// Ping 验证本地根目录可以创建和删除文件。
// @param ctx context.Context 调用上下文
// @return err error 目录不可用错误
func (s *Store) Ping(ctx context.Context) error {
	// 空存储对象无法执行健康检查。
	if s == nil {
		return uploadkit.ErrNilStore
	}
	// 健康检查统一要求调用方提供上下文。
	if ctx == nil {
		return uploadkit.ErrNilContext
	}
	// 已取消的请求不再访问文件系统。
	if err := ctx.Err(); err != nil {
		return err
	}
	// 在根目录创建最小临时文件验证写权限。
	file, err := os.CreateTemp(s.root, ".uploadkit-health-*")
	// 创建失败表示根目录当前不可写。
	if err != nil {
		return fmt.Errorf("check local store: %w", err)
	}
	// 保存临时文件路径供关闭后删除。
	fileName := file.Name()
	// 关闭文件并记录关闭结果。
	closeErr := file.Close()
	// 删除健康检查临时文件并记录结果。
	removeErr := os.Remove(fileName)
	// 任一清理步骤失败都返回健康检查错误。
	if closeErr != nil || removeErr != nil {
		return fmt.Errorf("check local store cleanup: %w", errors.Join(closeErr, removeErr))
	}
	// 根目录创建和删除能力正常。
	return nil
}

// objectPath 将安全对象键转换为本地绝对路径。
// @param objectKey string 对象键
// @return result string 本地路径
// @return err error 非法对象键错误
func (s *Store) objectPath(objectKey string) (result string, err error) {
	// 先使用核心规则校验对象键结构。
	if err = uploadkit.ValidateObjectKey(objectKey); err != nil {
		return "", err
	}
	// 本地文件系统还需要遵守当前操作系统的文件名规则。
	if err = validateLocalObjectKey(objectKey); err != nil {
		return "", err
	}
	// 将对象键的标准分隔符转换为本机路径并拼接根目录。
	targetPath := filepath.Join(s.root, filepath.FromSlash(objectKey))
	// 计算目标路径相对根目录的位置。
	relativePath, err := filepath.Rel(s.root, targetPath)
	// 相对路径解析失败或逃逸根目录时拒绝对象键。
	if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", uploadkit.ErrInvalidObjectKey
	}
	// 返回确认位于根目录内的目标路径。
	return targetPath, nil
}

// validateLocalObjectKey 校验当前操作系统特有的本地路径规则。
// @param objectKey string 对象键
// @return err error 非法本地对象键错误
func validateLocalObjectKey(objectKey string) error {
	// Unix 文件系统没有 Windows 设备名称和数据流路径语义。
	if runtime.GOOS != "windows" {
		return nil
	}
	// Windows 对象键使用专用规则校验每一个路径段。
	return validateWindowsObjectKey(objectKey)
}

// validateWindowsObjectKey 校验 Windows 文件名和设备名称规则。
// @param objectKey string 对象键
// @return err error 非法 Windows 对象键错误
func validateWindowsObjectKey(objectKey string) error {
	// 按对象键标准分隔符检查每一级目录和文件名称。
	for _, segment := range strings.Split(objectKey, "/") {
		// Windows 保留字符可能改变路径、通配符或数据流语义。
		if strings.ContainsAny(segment, `<>:"|?*`) {
			return uploadkit.ErrInvalidObjectKey
		}
		// Windows 会忽略名称末尾的点和空格，必须拒绝这种隐式改写。
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return uploadkit.ErrInvalidObjectKey
		}
		// 设备名称在附带普通扩展名时仍然保留特殊含义。
		baseName := segment
		if extensionIndex := strings.IndexByte(baseName, '.'); extensionIndex >= 0 {
			baseName = baseName[:extensionIndex]
		}
		// Windows 设备名称比较不区分大小写。
		if isWindowsDeviceName(strings.ToUpper(baseName)) {
			return uploadkit.ErrInvalidObjectKey
		}
	}
	// 全部路径段均可安全映射到 Windows 本地文件系统。
	return nil
}

// isWindowsDeviceName 判断名称是否属于 Windows 保留设备。
// @param name string 已转换为大写的基础名称
// @return result bool 是否为保留设备名称
func isWindowsDeviceName(name string) bool {
	// 无编号的系统设备名称始终保留。
	switch name {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	// COM1 至 COM9 和 LPT1 至 LPT9 也属于系统设备名称。
	if len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) {
		return name[3] >= '1' && name[3] <= '9'
	}
	// 其他名称可以作为普通本地路径段使用。
	return false
}

// ensureObjectDirectory 逐级创建对象目录并拒绝符号链接。
// @param directory string 对象所在目录
// @return err error 目录创建或边界错误
func (s *Store) ensureObjectDirectory(directory string) error {
	// 计算目标目录相对存储根目录的位置。
	relativePath, err := filepath.Rel(s.root, directory)
	if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return uploadkit.ErrInvalidObjectKey
	}
	// 根目录本身已经在初始化阶段完成创建和解析。
	if relativePath == "." {
		return nil
	}
	// current 保存当前已经确认安全的目录。
	current := s.root
	// 按路径层级依次检查或创建目录。
	for _, segment := range strings.Split(relativePath, string(filepath.Separator)) {
		// 将当前层级追加到已确认目录。
		current = filepath.Join(current, segment)
		// 使用 Lstat 检查目录本身，不跟随符号链接。
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			// 缺失目录只创建当前一级，避免 MkdirAll 跟随中间符号链接。
			if mkdirErr := os.Mkdir(current, s.directoryMode); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return fmt.Errorf("create local object directory: %w", mkdirErr)
			}
			// 并发创建完成后重新读取目录事实。
			info, statErr = os.Lstat(current)
		}
		// 目录状态读取失败时停止写入。
		if statErr != nil {
			return fmt.Errorf("inspect local object directory: %w", statErr)
		}
		// 符号链接和非目录节点都不能成为对象路径。
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return uploadkit.ErrInvalidObjectKey
		}
	}
	// 所有目录层级都位于受控根目录内。
	return nil
}

// copyWithContext 流式写入对象并及时响应取消。
// @param ctx context.Context 调用上下文
// @param destination io.Writer 写入目标
// @param source io.Reader 内容来源
// @return written int64 写入字节数
// @return err error 上下文或读写错误
func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (written int64, err error) {
	// 每次本地写入使用固定大小缓冲区限制内存占用。
	buffer := make([]byte, copyBufferSize)
	// 持续复制直到读取完成、取消或出现错误。
	for {
		// 每个数据块读取前响应上下文取消。
		if err = ctx.Err(); err != nil {
			return written, err
		}
		// 从对象内容读取下一个数据块。
		readCount, readErr := source.Read(buffer)
		// 当前数据块非空时写入临时文件。
		if readCount > 0 {
			// 写入本次实际读取的数据范围。
			writeCount, writeErr := destination.Write(buffer[:readCount])
			// 累加已经写入的字节数量。
			written += int64(writeCount)
			// 写入失败时返回已完成数量和错误。
			if writeErr != nil {
				return written, writeErr
			}
			// 无错误但写入不完整时返回标准短写错误。
			if writeCount != readCount {
				return written, io.ErrShortWrite
			}
		}
		// 读取返回状态时处理完成或失败分支。
		if readErr != nil {
			// EOF 表示对象内容已经完整写入。
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			// 其他读取错误保留已写入数量并返回。
			return written, readErr
		}
	}
}
