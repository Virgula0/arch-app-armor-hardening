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

// === Fscrypt Subsystem (Key management, NO migration) ===

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
		return nil // already unlocked (e.g. on SIGHUP reload)
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

	// There's exactly one raw_key protector on this policy — always pick it.
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

// hasEncryptionPolicy returns true if dirPath already has an fscrypt policy (v1 or v2).
func hasEncryptionPolicy(dirPath string) (bool, error) {
	dirFd, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", dirPath, err)
	}
	defer unix.Close(dirFd)

	var arg unix.FscryptGetPolicyExArg
	arg.Size = 24 // size of the policy union inside the kernel structure

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(dirFd),
		uintptr(linux_FS_IOC_GET_ENCRYPTION_POLICY_EX),
		uintptr(unsafe.Pointer(&arg)),
	)

	if errno == 0 {
		return true, nil
	}

	// ENODATA – no policy present; EOPNOTSUPP – filesystem doesn’t support fscrypt at all
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
				Entry: Entry{Dev: st.Dev, Ino: st.Ino, Path: dirPath},
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

// === TOCTOU-Resistant Identity Validation ===

func isAllowed(pid int32, evFd int32) bool {
	fdLink := fmt.Sprintf("/proc/self/fd/%d", evFd)
	filePath, err := os.Readlink(fdLink)
	if err != nil {
		return false
	}

	var dirSt unix.Stat_t
	if err := unix.Stat(filepath.Dir(filePath), &dirSt); err != nil {
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
		// Detailed log – shows the denied process, the file it tried to open, and the watched directory
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
		excludeMap := make(map[string]bool)
		for _, ex := range w.ExcludedFiles {
			excludeMap[ex] = true
		}

		_ = filepath.WalkDir(w.Path, func(path string, d os.DirEntry, err error) error {
			if err != nil || path == w.Path {
				return nil
			}
			if !d.Type().IsRegular() && !d.IsDir() {
				return nil
			}
			enable := !excludeMap[d.Name()]
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

	// -- HARD REQUIREMENT: all watched directories must be encrypted --
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

	// Inject the master key into the kernel for every watched directory
	for _, w := range wEntries {
		if err := unlockWithFscrypt(w.Path); err != nil {
			logMsg(syslog.LOG_ERR, "Failed to inject fscrypt key for %s: %v", w.Path, err)
			os.Exit(1)
		}
	}

	pidData := fmt.Sprintf("%d\n", os.Getpid())
	os.WriteFile(PidFile, []byte(pidData), 0644)
	defer os.Remove(PidFile)

	// Re‑apply immutable/append‑only attributes – they may have been cleared by migration
	applyChattr(ctx.watchEntries)

	fanFd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fanotify initialization failure: %v", err)
		os.Exit(1)
	}
	defer unix.Close(fanFd)

	addAllMarks(fanFd, ctx.watchEntries)

	// Signal systemd that we are ready (keys injected, marks active)
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
				unix.FanotifyMark(fanFd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, "/")
				if newEntries, err := loadConfig(); err == nil {
					ctx.Lock()
					ctx.watchEntries = newEntries
					ctx.Unlock()
					applyChattr(newEntries)
					addAllMarks(fanFd, newEntries)
				}
			case syscall.SIGTERM, syscall.SIGINT:
				unix.Close(fanFd)
				ctx.RLock()
				currentWatches := ctx.watchEntries
				ctx.RUnlock()
				revertChattr(currentWatches)
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
				if isAllowed(ev.Pid, ev.Fd) {
					response = unix.FAN_ALLOW
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
