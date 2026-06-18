package main

import (
	"bufio"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// === Configuration Constants ===

const (
	ConfigPath = "/etc/ssh-guard/config"
	PidFile    = "/run/ssh-guard.pid"
)

const (
	linux_FS_IOC_GETFLAGS = 0x80086601
	linux_FS_IOC_SETFLAGS = 0x40086602
	linux_FS_IMMUTABLE_FL = 0x00000010
	linux_FS_APPEND_FL    = 0x00000020
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

// === Global Context (Protected by RWMutex) ===

type SecurityContext struct {
	sync.RWMutex
	watchEntries []WatchEntry
	syslogW      *syslog.Writer
	isTerminal   bool
}

var ctx = &SecurityContext{}

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
			logMsg(syslog.LOG_INFO, "Watch Target Registered: %s (ino=%d)", dirPath, st.Ino)
			continue
		}

		if currentIdx < 0 {
			continue
		}

		if strings.HasPrefix(line, "exclude_chattr ") {
			excluded := strings.TrimSpace(strings.TrimPrefix(line, "exclude_chattr "))
			watches[currentIdx].ExcludedFiles = append(watches[currentIdx].ExcludedFiles, excluded)
			logMsg(syslog.LOG_INFO, "Chattr Exclusion Registered: %s", excluded)
			continue
		}

		var st unix.Stat_t
		if err := unix.Stat(line, &st); err != nil {
			logMsg(syslog.LOG_WARNING, "Skipping missing or unreadable path: %s", line)
			continue
		}

		watches[currentIdx].AllowedBins = append(watches[currentIdx].AllowedBins, Entry{
			Dev:  st.Dev,
			Ino:  st.Ino,
			Path: line,
		})
		logMsg(syslog.LOG_INFO, "White-listed Binary Registered: %s (ino=%d)", line, st.Ino)
	}

	return watches, scanner.Err()
}

// === TOCTOU-Resistant Identity Validation ===

func isAllowed(pid int32, evFd int32) bool {
	fdLink := fmt.Sprintf("/proc/self/fd/%d", evFd)
	filePath, err := os.Readlink(fdLink)
	if err != nil {
		logMsg(syslog.LOG_WARNING, "isAllowed: readlink %s failed: %v", fdLink, err)
		return false
	}

	var dirSt unix.Stat_t
	if err := unix.Stat(filepath.Dir(filePath), &dirSt); err != nil {
		logMsg(syslog.LOG_WARNING, "isAllowed: stat parent of %s failed: %v", filePath, err)
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
		exePath, err := os.Readlink(procExe)
		if err != nil {
			exePath = "<unknown>"
		}
		logMsg(syslog.LOG_WARNING, "DENIED access tracking -> pid=%-6d exe=%s dev=%d ino=%d dir=%s",
			pid, exePath, exeSt.Dev, exeSt.Ino, watch.Path)
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
	// Note: This addition routing through /proc/1/root bypasses systemd ProtectSystem=strict read-only sandboxes.
	// It works for Arch Linux, linux-hardened setups, and universally on any systemd restricted mounts.
	realPath := path
	if filepath.IsAbs(path) {
		realPath = filepath.Join("/proc/1/root", path)
	}

	f, err := os.Open(realPath)
	if err != nil {
		f, err = os.Open(path)
		if err != nil {
			return err
		}
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

		err := filepath.WalkDir(w.Path, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				logMsg(syslog.LOG_WARNING, "WalkDir skipped %s: %v", path, err)
				return nil
			}
			if path == w.Path {
				return nil
			}

			// Skip sockets, symlinks, pipes, and devices. open() on a socket throws ENXIO
			if !d.Type().IsRegular() && !d.IsDir() {
				return nil
			}

			enable := true
			if excludeMap[d.Name()] {
				enable = false
			}

			if chattrErr := modifyChattr(path, linux_FS_IMMUTABLE_FL, enable); chattrErr != nil {
				logMsg(syslog.LOG_WARNING, "Skipped chattr modification on %s: %v", path, chattrErr)
			}

			return nil
		})
		if err != nil {
			logMsg(syslog.LOG_ERR, "Failed recursive +i walk on %s: %v", w.Path, err)
		}

		err = modifyChattr(w.Path, linux_FS_APPEND_FL, true)
		if err != nil {
			logMsg(syslog.LOG_ERR, "Failed +a on %s: %v", w.Path, err)
		}
	}
}

// === Application Entrypoint ===

func main() {
	var err error
	ctx.isTerminal = checkTerminal()

	ctx.syslogW, err = syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ssh-guard")
	if err != nil {
		log.Fatalf("Initialization error breaking syslog target binding: %v", err)
	}
	defer ctx.syslogW.Close()

	logMsg(syslog.LOG_INFO, "ssh-guard starting daemon infrastructure (pid %d)", os.Getpid())

	pidData := fmt.Sprintf("%d\n", os.Getpid())
	if err := os.WriteFile(PidFile, []byte(pidData), 0644); err != nil {
		logMsg(syslog.LOG_ERR, "Could not write running context process trace file: %v", err)
	}
	defer os.Remove(PidFile)

	wEntries, err := loadConfig()
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fatal configuration load failure: %v", err)
		os.Exit(1)
	}
	ctx.watchEntries = wEntries

	applyChattr(ctx.watchEntries)

	fanFd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fanotify structural initialization failure: %v (Are you root?)", err)
		os.Exit(1)
	}
	defer unix.Close(fanFd)

	addAllMarks(fanFd, ctx.watchEntries)
	logMsg(syslog.LOG_INFO, "Daemon functional framework active. Enforcing strict structural baseline.")

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				logMsg(syslog.LOG_INFO, "SIGHUP intercepted - updating active policies")

				_ = unix.FanotifyMark(fanFd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, "/")

				if newEntries, err := loadConfig(); err == nil {
					ctx.Lock()
					ctx.watchEntries = newEntries
					ctx.Unlock()

					applyChattr(newEntries)
					addAllMarks(fanFd, newEntries)
					logMsg(syslog.LOG_INFO, "Dynamic structural configuration hot-reload complete")
				} else {
					logMsg(syslog.LOG_ERR, "Aborting policy hot-reload due to configuration errors: %v", err)
				}

			case syscall.SIGTERM, syscall.SIGINT:
				logMsg(syslog.LOG_INFO, "Termination request processed. Shutting down...")
				unix.Close(fanFd)
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
			logMsg(syslog.LOG_ERR, "Fanotify read context state broken: %v", err)
			break
		}

		offset := 0
		for offset+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) <= n {
			ev := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))

			if ev.Vers != unix.FANOTIFY_METADATA_VERSION {
				logMsg(syslog.LOG_ERR, "Critical mismatch on kernel subsystem ABI version metadata: %d", ev.Vers)
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
				if _, err := unix.Write(fanFd, respBytes); err != nil {
					logMsg(syslog.LOG_ERR, "Failed to dispatch intercept evaluation message back to kernel: %v", err)
				}
			}

			if ev.Fd >= 0 {
				unix.Close(int(ev.Fd))
			}

			offset += int(ev.Event_len)
		}
	}
}
