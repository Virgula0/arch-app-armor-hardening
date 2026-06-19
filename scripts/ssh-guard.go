package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/fscrypt/actions"
	"github.com/google/fscrypt/crypto"
	"golang.org/x/sys/unix"
)

// === Configuration Constants ===
const (
	ConfigPath     = "/etc/ssh-guard/config"
	PidFile        = "/run/ssh-guard.pid"
	MasterKeyFile  = "/etc/ssh-guard/fscrypt.key"
	FscryptKeySize = 32 // AES-256-CTS master key length
)

const (
	linux_FS_IOC_GETFLAGS = 0x80086601
	linux_FS_IOC_SETFLAGS = 0x40086602
	linux_FS_IMMUTABLE_FL = 0x00000010
	linux_FS_APPEND_FL    = 0x00000020
	// FS_IOC_GET_ENCRYPTION_POLICY_EX – used to detect any fscrypt policy (v1 or v2)
	linux_FS_IOC_GET_ENCRYPTION_POLICY_EX = 0xc0096616
)

// === fanotify pidfd-reporting constants ===
// Defined locally (rather than relying on golang.org/x/sys/unix to export
// them under these exact names) so the patch doesn't depend on a specific
// x/sys version. Values come straight from the kernel's
// include/uapi/linux/fanotify.h.
const (
	localFanReportPidfd         = 0x00000080 // FAN_REPORT_PIDFD
	fanEventInfoTypePidfd       = 0x04       // FAN_EVENT_INFO_TYPE_PIDFD
	fanNoPidfd            int32 = -1         // FAN_NOPIDFD
	fanEPidfd             int32 = -2         // FAN_EPIDFD
)

// fanotifyEventInfoHeader / fanotifyEventInfoPidfd mirror the kernel structs:
type fanotifyEventInfoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

type fanotifyEventInfoPidfd struct {
	Hdr   fanotifyEventInfoHeader
	Pidfd int32
}

// === Types ===
type Entry struct {
	Dev  uint64
	Ino  uint64
	Path string
}

type WatchEntry struct {
	Entry
	AllowedBins   []Entry
	ExcludedFiles []string
	ExcludeSet    map[string]bool
}

type SecurityContext struct {
	sync.RWMutex
	watchEntries []WatchEntry
	syslogW      *syslog.Writer
	isTerminal   bool
}

var ctx = &SecurityContext{}

type fscryptAddKeyArgFull struct {
	Header unix.FscryptAddKeyArg
	Raw    [FscryptKeySize]byte
}

// === Logging System ===
func logMsg(prio syslog.Priority, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	if ctx.syslogW != nil {
		switch prio {
		case syslog.LOG_ERR:
			_ = ctx.syslogW.Err(msg)
		case syslog.LOG_WARNING:
			_ = ctx.syslogW.Warning(msg)
		case syslog.LOG_INFO:
			_ = ctx.syslogW.Info(msg)
		}
	}
	if ctx.isTerminal {
		fmt.Fprintln(os.Stderr, msg)
	}
}

func checkTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS)
	return err == nil
}

// === Fscrypt Subsystem ===
func getOrGenerateKey() ([]byte, error) {
	key := make([]byte, FscryptKeySize)
	f, err := os.OpenFile(MasterKeyFile, os.O_RDONLY, 0400)
	if err == nil {
		defer f.Close()
		if _, err := io.ReadFull(f, key); err != nil {
			return nil, fmt.Errorf("failed to read master key: %w", err)
		}
		return key, nil
	}
	if os.IsNotExist(err) {
		logMsg(syslog.LOG_INFO, "Generating new fscrypt master key...")
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		f, err = os.OpenFile(MasterKeyFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err := f.Write(key); err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, err
}

func unlockWithFscrypt(dirPath string) error {
	fsctx, err := actions.NewContextFromPath(dirPath, nil) // nil = current user (root)
	if err != nil {
		return fmt.Errorf("fscrypt context for %s: %w", dirPath, err)
	}
	policy, err := actions.GetPolicyFromPath(fsctx, dirPath)
	if err != nil {
		return fmt.Errorf("get policy for %s: %w", dirPath, err)
	}
	if policy.IsProvisionedByTargetUser() {
		return nil // already unlocked
	}
	keyBytes, err := os.ReadFile(MasterKeyFile)
	if err != nil {
		return fmt.Errorf("read master key: %w", err)
	}
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()
	optionFn := func(_ string, _ []*actions.ProtectorOption) (int, error) {
		return 0, nil
	}
	keyFn := func(_ actions.ProtectorInfo, _ bool) (*crypto.Key, error) {
		return crypto.NewFixedLengthKeyFromReader(bytes.NewReader(keyBytes), FscryptKeySize)
	}
	if err := policy.Unlock(optionFn, keyFn); err != nil {
		return fmt.Errorf("unlock policy for %s: %w", dirPath, err)
	}
	defer policy.Lock()
	if err := policy.Provision(); err != nil {
		return fmt.Errorf("provision policy for %s: %w", dirPath, err)
	}
	return nil
}

// lockWithFscrypt removes the key from the kernel keyring and drops VFS caches
func lockWithFscrypt(dirPath string) error {
	fsctx, err := actions.NewContextFromPath(dirPath, nil)
	if err != nil {
		return fmt.Errorf("fscrypt context for %s: %w", dirPath, err)
	}
	policy, err := actions.GetPolicyFromPath(fsctx, dirPath)
	if err != nil {
		return fmt.Errorf("get policy for %s: %w", dirPath, err)
	}
	if !policy.IsProvisionedByTargetUser() {
		return nil // already locked
	}
	// Deprovision(true) clears the key and drops cached inodes/pages
	if err := policy.Deprovision(true); err != nil {
		return fmt.Errorf("deprovision policy for %s: %w", dirPath, err)
	}
	return nil
}

func hasEncryptionPolicy(dirPath string) (bool, error) {
	dirFd, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", dirPath, err)
	}
	defer unix.Close(dirFd)
	var arg unix.FscryptGetPolicyExArg
	arg.Size = 24
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(dirFd),
		uintptr(linux_FS_IOC_GET_ENCRYPTION_POLICY_EX),
		uintptr(unsafe.Pointer(&arg)),
	)
	if errno == 0 {
		return true, nil
	}
	if errors.Is(errno, unix.ENODATA) || errors.Is(errno, unix.EOPNOTSUPP) {
		return false, nil
	}
	return false, fmt.Errorf("ioctl GET_ENCRYPTION_POLICY_EX on %s: %w", dirPath, errno)
}

// === Configuration Parser ===
func loadConfig() ([]WatchEntry, error) {
	file, err := os.Open(ConfigPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var watches []WatchEntry
	currentIdx := -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[watch ") && strings.HasSuffix(line, "]") {
			dirPath := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[watch "), "]"))
			var st unix.Stat_t
			if err := unix.Stat(dirPath, &st); err != nil {
				logMsg(syslog.LOG_WARNING, "Skipping missing or unreadable path: %s", dirPath)
				currentIdx = -1
				continue
			}
			watches = append(watches, WatchEntry{
				Entry:      Entry{Dev: st.Dev, Ino: st.Ino, Path: dirPath},
				ExcludeSet: make(map[string]bool),
			})
			currentIdx = len(watches) - 1
			continue
		}
		if currentIdx < 0 {
			continue
		}
		if strings.HasPrefix(line, "exclude_chattr ") {
			excluded := strings.TrimSpace(strings.TrimPrefix(line, "exclude_chattr "))
			watches[currentIdx].ExcludedFiles = append(watches[currentIdx].ExcludedFiles, excluded)
			watches[currentIdx].ExcludeSet[excluded] = true
			continue
		}
		var st unix.Stat_t
		if err := unix.Stat(line, &st); err != nil {
			continue
		}
		watches[currentIdx].AllowedBins = append(watches[currentIdx].AllowedBins, Entry{
			Dev:  st.Dev,
			Ino:  st.Ino,
			Path: line,
		})
	}
	return watches, scanner.Err()
}

// === pidfd identity resolution ===
func extractPidfd(buf []byte, evStart, evLen int) (int32, bool) {
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	pos := evStart + metaSize
	end := evStart + evLen
	for pos+4 <= end && pos+4 <= len(buf) {
		hdr := (*fanotifyEventInfoHeader)(unsafe.Pointer(&buf[pos]))
		recLen := int(hdr.Len)
		if recLen < 4 || pos+recLen > end || pos+recLen > len(buf) {
			break
		}
		if hdr.InfoType == fanEventInfoTypePidfd && recLen >= 8 {
			rec := (*fanotifyEventInfoPidfd)(unsafe.Pointer(&buf[pos]))
			return rec.Pidfd, true
		}
		pos += recLen
	}
	return 0, false
}

func resolvePidFromPidfd(pidfd int32) (int, error) {
	fdinfoPath := fmt.Sprintf("/proc/self/fdinfo/%d", pidfd)
	data, err := os.ReadFile(fdinfoPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", fdinfoPath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Pid:") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return 0, fmt.Errorf("malformed Pid line in %s", fdinfoPath)
			}
			var pid int
			if _, err := fmt.Sscanf(fields[1], "%d", &pid); err != nil {
				return 0, fmt.Errorf("parse pid in %s: %w", fdinfoPath, err)
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("no Pid field in %s", fdinfoPath)
}

// === TOCTOU-Resistant Identity Validation ===
func isAllowed(pidfd int32, evFd int32) bool {
	if pidfd == fanNoPidfd || pidfd == fanEPidfd || pidfd < 0 {
		logMsg(syslog.LOG_WARNING, "DENIED: event carried no usable pidfd (raw=%d) — failing closed", pidfd)
		return false
	}
	defer unix.Close(int(pidfd))

	fdLink := fmt.Sprintf("/proc/self/fd/%d", evFd)
	filePath, err := os.Readlink(fdLink)
	if err != nil {
		return false
	}
	var dirSt unix.Stat_t
	if err := unix.Stat(filepath.Dir(filePath), &dirSt); err != nil {
		return false
	}

	pid, err := resolvePidFromPidfd(pidfd)
	if err != nil {
		logMsg(syslog.LOG_WARNING, "DENIED: could not resolve pid from pidfd: %v", err)
		return false
	}

	procExe := fmt.Sprintf("/proc/%d/exe", pid)
	exeFd, err := unix.Open(procExe, unix.O_RDONLY|unix.O_PATH, 0)
	if err != nil {
		return false
	}
	defer unix.Close(exeFd)
	var exeSt unix.Stat_t
	if err := unix.Fstat(exeFd, &exeSt); err != nil {
		return false
	}

	if err := unix.PidfdSendSignal(int(pidfd), 0, nil, 0); err != nil {
		logMsg(syslog.LOG_WARNING, "DENIED: process behind pidfd %d no longer alive: %v", pidfd, err)
		return false
	}

	ctx.RLock()
	defer ctx.RUnlock()
	for _, watch := range ctx.watchEntries {
		if watch.Dev != dirSt.Dev || watch.Ino != dirSt.Ino {
			continue
		}
		for _, bin := range watch.AllowedBins {
			if bin.Dev == exeSt.Dev && bin.Ino == exeSt.Ino {
				return true
			}
		}
		exePath, _ := os.Readlink(procExe)
		logMsg(syslog.LOG_WARNING,
			"DENIED access tracking -> pid=%-6d exe=%s file=%s dev=%d ino=%d dir=%s",
			pid, exePath, filePath, dirSt.Dev, dirSt.Ino, watch.Path)
		return false
	}
	return false
}

// === Fanotify Operational Helpers ===
func addAllMarks(fanFd int, watches []WatchEntry) {
	for _, target := range watches {
		mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_EVENT_ON_CHILD)
		err := unix.FanotifyMark(fanFd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, target.Path)
		if err != nil {
			logMsg(syslog.LOG_ERR, "Failed mapping mark on target %s: %v", target.Path, err)
		}
	}
}

func reconcileMarks(fanFd int, oldWatches, newWatches []WatchEntry) {
	addAllMarks(fanFd, newWatches)

	newSet := make(map[string]bool, len(newWatches))
	for _, w := range newWatches {
		newSet[w.Path] = true
	}
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_EVENT_ON_CHILD)
	for _, w := range oldWatches {
		if newSet[w.Path] {
			continue
		}
		if err := unix.FanotifyMark(fanFd, unix.FAN_MARK_REMOVE, mask, unix.AT_FDCWD, w.Path); err != nil {
			logMsg(syslog.LOG_WARNING, "Failed to remove stale mark on %s: %v", w.Path, err)
		}
	}
}

func modifyChattr(path string, flag uint32, enable bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fd := f.Fd()
	var flags uint32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(linux_FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errno
	}
	if enable {
		flags |= flag
	} else {
		flags &^= flag
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(linux_FS_IOC_SETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errno
	}
	return nil
}

func applyChattr(watches []WatchEntry) {
	for _, w := range watches {
		_ = filepath.WalkDir(w.Path, func(path string, d os.DirEntry, err error) error {
			if err != nil || path == w.Path {
				return nil
			}
			if !d.Type().IsRegular() && !d.IsDir() {
				return nil
			}
			enable := !w.ExcludeSet[d.Name()]
			if chattrErr := modifyChattr(path, linux_FS_IMMUTABLE_FL, enable); chattrErr != nil {
				logMsg(syslog.LOG_WARNING, "chattr +i failed on %s: %v", path, chattrErr)
			}
			return nil
		})
		if chattrErr := modifyChattr(w.Path, linux_FS_APPEND_FL, true); chattrErr != nil {
			logMsg(syslog.LOG_WARNING, "chattr +a failed on %s: %v", w.Path, chattrErr)
		}
	}
}

func revertChattr(watches []WatchEntry) {
	for _, w := range watches {
		modifyChattr(w.Path, linux_FS_APPEND_FL, false)
		_ = filepath.WalkDir(w.Path, func(path string, d os.DirEntry, err error) error {
			if err != nil || path == w.Path {
				return nil
			}
			if !d.Type().IsRegular() && !d.IsDir() {
				return nil
			}
			modifyChattr(path, linux_FS_IMMUTABLE_FL, false)
			return nil
		})
	}
}

// === Create-time hardening ===
type createWatchState struct {
	sync.RWMutex
	fd      int
	wdToDir map[int32]WatchEntry
}

var createWatcher = &createWatchState{}

func startCreateWatcher() error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	createWatcher.fd = fd
	createWatcher.wdToDir = make(map[int32]WatchEntry)
	go runCreateWatcherLoop()
	return nil
}

func reconcileCreateWatches(watches []WatchEntry) {
	createWatcher.Lock()
	defer createWatcher.Unlock()
	for wd := range createWatcher.wdToDir {
		unix.InotifyRmWatch(createWatcher.fd, uint32(wd))
	}
	createWatcher.wdToDir = make(map[int32]WatchEntry)
	for _, w := range watches {
		wd, err := unix.InotifyAddWatch(createWatcher.fd, w.Path, unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO)
		if err != nil {
			logMsg(syslog.LOG_WARNING, "Failed to add create-watch on %s: %v", w.Path, err)
			continue
		}
		createWatcher.wdToDir[int32(wd)] = w
	}
}

const inotifyEventHeaderSize = int(unsafe.Sizeof(unix.InotifyEvent{}))

func runCreateWatcherLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(createWatcher.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			// Catch the expected error when the main thread closes the FD during shutdown
			if err == unix.EBADF || strings.Contains(err.Error(), "bad file descriptor") {
				logMsg(syslog.LOG_INFO, "create-watcher loop cleanly exited.")
				return
			}
			logMsg(syslog.LOG_ERR, "create-watcher read failed, stopping: %v", err)
			return
		}
		offset := 0
		for offset+inotifyEventHeaderSize <= n {
			raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(raw.Len)
			var name string
			if nameLen > 0 && offset+inotifyEventHeaderSize+nameLen <= n {
				nameBytes := buf[offset+inotifyEventHeaderSize : offset+inotifyEventHeaderSize+nameLen]
				name = strings.TrimRight(string(nameBytes), "\x00")
			}
			offset += inotifyEventHeaderSize + nameLen

			if name == "" {
				continue
			}
			createWatcher.RLock()
			watch, ok := createWatcher.wdToDir[raw.Wd]
			createWatcher.RUnlock()
			if !ok {
				continue
			}
			if watch.ExcludeSet[name] {
				continue
			}
			fullPath := filepath.Join(watch.Path, name)
			if err := modifyChattr(fullPath, linux_FS_IMMUTABLE_FL, true); err != nil {
				logMsg(syslog.LOG_WARNING, "Failed to immediately protect new file %s: %v", fullPath, err)
			} else {
				logMsg(syslog.LOG_INFO, "Applied +i immediately to new file %s", fullPath)
			}
		}
	}
}

// === Application Entrypoint ===
func main() {
	genKey := flag.Bool("genkey", false, "Generate master key file and exit")
	flag.Parse()

	var err error
	ctx.isTerminal = checkTerminal()
	ctx.syslogW, _ = syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ssh-guard")
	if ctx.syslogW != nil {
		defer ctx.syslogW.Close()
	}

	if *genKey {
		os.MkdirAll(filepath.Dir(MasterKeyFile), 0700)
		_, err := getOrGenerateKey()
		if err != nil {
			logMsg(syslog.LOG_ERR, "Failed to generate master key: %v", err)
			os.Exit(1)
		}
		logMsg(syslog.LOG_INFO, "Master key ready at %s", MasterKeyFile)
		return
	}

	logMsg(syslog.LOG_INFO, "ssh-guard daemon starting (pid %d)", os.Getpid())
	os.MkdirAll("/etc/ssh-guard", 0700)

	wEntries, err := loadConfig()
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fatal configuration load failure: %v", err)
		os.Exit(1)
	}
	ctx.watchEntries = wEntries

	var missing []string
	for _, w := range wEntries {
		encrypted, err := hasEncryptionPolicy(w.Path)
		if err != nil {
			logMsg(syslog.LOG_ERR, "Failed to check encryption on %s: %v", w.Path, err)
			os.Exit(1)
		}
		if !encrypted {
			logMsg(syslog.LOG_ERR, "Directory %s is NOT encrypted. Run the migration script first.", w.Path)
			missing = append(missing, w.Path)
		} else {
			logMsg(syslog.LOG_INFO, "Encryption verified for %s", w.Path)
		}
	}
	if len(missing) > 0 {
		os.Exit(1)
	}

	for _, w := range wEntries {
		if err := unlockWithFscrypt(w.Path); err != nil {
			logMsg(syslog.LOG_ERR, "Failed to inject fscrypt key for %s: %v", w.Path, err)
			os.Exit(1)
		}
	}

	pidData := fmt.Sprintf("%d\n", os.Getpid())
	os.WriteFile(PidFile, []byte(pidData), 0644)
	defer os.Remove(PidFile)

	applyChattr(ctx.watchEntries)

	fanFd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|localFanReportPidfd, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fanotify initialization failure: %v", err)
		os.Exit(1)
	}
	defer unix.Close(fanFd)
	addAllMarks(fanFd, ctx.watchEntries)

	if err := startCreateWatcher(); err != nil {
		logMsg(syslog.LOG_ERR, "Failed to start create-watcher: %v", err)
		os.Exit(1)
	}
	reconcileCreateWatches(ctx.watchEntries)

	if notifySocket := os.Getenv("NOTIFY_SOCKET"); notifySocket != "" {
		conn, err := net.Dial("unixgram", notifySocket)
		if err == nil {
			conn.Write([]byte("READY=1"))
			conn.Close()
		}
	}

	logMsg(syslog.LOG_INFO, "Daemon functional framework active. All directories encrypted and hardened.")

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				newEntries, err := loadConfig()
				if err != nil {
					logMsg(syslog.LOG_ERR, "Reload failed, keeping previous configuration: %v", err)
					continue
				}

				ctx.Lock()
				oldEntries := ctx.watchEntries
				ctx.watchEntries = newEntries
				ctx.Unlock()

				applyChattr(newEntries)
				reconcileMarks(fanFd, oldEntries, newEntries)
				reconcileCreateWatches(newEntries)
				logMsg(syslog.LOG_INFO, "Configuration reloaded without dropping fanotify protection")

			case syscall.SIGTERM, syscall.SIGINT:
				logMsg(syslog.LOG_INFO, "Caught termination signal. Shutting down safely...")

				// 1. Synchronously flush all fanotify marks before closing
				unix.FanotifyMark(fanFd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, "")
				unix.Close(fanFd)

				// 2. Synchronously remove all inotify watches before closing
				createWatcher.Lock()
				for wd := range createWatcher.wdToDir {
					unix.InotifyRmWatch(createWatcher.fd, uint32(wd))
				}
				if createWatcher.fd > 0 {
					unix.Close(createWatcher.fd)
				}
				createWatcher.Unlock()

				ctx.RLock()
				currentWatches := ctx.watchEntries
				ctx.RUnlock()

				// 3. Revert immutable/append-only flags
				revertChattr(currentWatches)

				// 4. Yield to the kernel. This gives the Linux VFS scheduler time
				// to execute the delayed fput() tasks and clear RCU grace periods
				// generated by closing the watchers and reverting chattr.
				time.Sleep(500 * time.Millisecond)

				// 5. Securely deprovision fscrypt keys
				for _, w := range currentWatches {
					if err := lockWithFscrypt(w.Path); err != nil {
						// Check if the error is the expected VFS busy state
						if strings.Contains(err.Error(), "some files using the key are still open") {
							logMsg(syslog.LOG_WARNING, "Partial lock on %s: Master key wiped from kernel, but external processes (e.g., ssh-agent, NetworkManager) are holding files open. Cached data stays in RAM until they exit.", w.Path)
						} else {
							logMsg(syslog.LOG_ERR, "Failed to lock %s: %v", w.Path, err)
						}
					} else {
						logMsg(syslog.LOG_INFO, "Locked fscrypt directory fully: %s", w.Path)
					}
				}

				logMsg(syslog.LOG_INFO, "Shutdown complete.")
				os.Exit(0)
			}
		}
	}()

	var buf [16384]byte
	for {
		n, err := unix.Read(fanFd, buf[:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			break
		}
		offset := 0
		for offset+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) <= n {
			ev := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if ev.Vers != unix.FANOTIFY_METADATA_VERSION {
				os.Exit(1)
			}
			if ev.Mask&uint64(unix.FAN_OPEN_PERM|unix.FAN_ACCESS_PERM) != 0 {
				var response uint32 = unix.FAN_DENY
				if pidfd, ok := extractPidfd(buf[:], offset, int(ev.Event_len)); ok {
					if isAllowed(pidfd, ev.Fd) {
						response = unix.FAN_ALLOW
					}
				} else {
					logMsg(syslog.LOG_WARNING, "DENIED: event for pid=%d carried no pidfd info record - failing closed", ev.Pid)
				}
				resp := unix.FanotifyResponse{
					Fd:       ev.Fd,
					Response: response,
				}
				respBytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), int(unsafe.Sizeof(resp)))
				unix.Write(fanFd, respBytes)
			}
			if ev.Fd >= 0 {
				unix.Close(int(ev.Fd))
			}
			offset += int(ev.Event_len)
		}
	}
}
