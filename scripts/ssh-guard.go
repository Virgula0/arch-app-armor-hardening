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

// === Types ===

type Entry struct {
	Dev  uint64
	Ino  uint64
	Path string
}

type WatchEntry struct {
	Entry
	AllowedBins []Entry
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

// logMsg routes logs to both system syslog and stdout/stderr if run interactively.
func logMsg(prio syslog.Priority, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)

	// Write to system log
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

	// Mirror to stderr if running in a TTY environment
	if ctx.isTerminal {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// checkTerminal asserts if Stderr is a standard attached terminal (isatty alternative)
func checkTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS)
	return err == nil
}

// === Configuration Parser ===

// loadConfig reads the config path, parsing [watch <dir>] sections each with their own allowed binary list
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
		// Skip empty entries and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[watch ") && strings.HasSuffix(line, "]") {
			dirPath := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[watch "), "]"))

			// Retrieve device identity metadata via system Stat
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

		// Retrieve device identity metadata via system Stat
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

// isAllowed verifies the process backing data using the O_PATH + Fstat technique,
// matching the accessed file's parent directory against per-directory allowlists
func isAllowed(pid int32, evFd int32) bool {
	// Resolve the accessed file's path via its proc fd symlink, then derive the
	// parent directory with filepath.Dir and confirm its identity by Stat.
	// readlink on a proc magic link is reliable from inside the service's mount
	// namespace; it avoids the "/proc/self/fd/N/.." path-component traversal which
	// fails silently under ProtectSystem=strict's private mount namespace.
	// The subsequent inode comparison closes any TOCTOU window: a renamed or
	// swapped directory changes its inode on a given device.
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

	// O_PATH optimization avoids full data reads or actual access checks on targets
	procExe := fmt.Sprintf("/proc/%d/exe", pid)
	exeFd, err := unix.Open(procExe, unix.O_RDONLY|unix.O_PATH, 0)
	if err != nil {
		// Process vanished or detached since trigger event occurred - strict default deny
		return false
	}
	defer unix.Close(exeFd)

	var exeSt unix.Stat_t
	if err := unix.Fstat(exeFd, &exeSt); err != nil {
		return false
	}

	// Dynamic safe read-lock evaluation of our global rules
	ctx.RLock()
	defer ctx.RUnlock()

	for _, watch := range ctx.watchEntries {
		if watch.Dev != dirSt.Dev || watch.Ino != dirSt.Ino {
			continue
		}
		// Matched the watch directory -- check against its specific allowlist
		for _, bin := range watch.AllowedBins {
			if bin.Dev == exeSt.Dev && bin.Ino == exeSt.Ino {
				return true
			}
		}
		// Map explicit human-readable string trace for rejection records
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

// === Application Entrypoint ===

func main() {
	var err error
	ctx.isTerminal = checkTerminal()

	// Establish logging bindings (LOG_INFO set as baseline; Go handles the PID inclusion automatically)
	ctx.syslogW, err = syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ssh-guard")
	if err != nil {
		log.Fatalf("Initialization error breaking syslog target binding: %v", err)
	}
	defer ctx.syslogW.Close()

	logMsg(syslog.LOG_INFO, "ssh-guard starting daemon infrastructure (pid %d)", os.Getpid())

	// Persist Daemon PID metadata mapping
	pidData := fmt.Sprintf("%d\n", os.Getpid())
	if err := os.WriteFile(PidFile, []byte(pidData), 0644); err != nil {
		logMsg(syslog.LOG_ERR, "Could not write running context process trace file: %v", err)
	}
	defer os.Remove(PidFile)

	// Context configuration ingestion
	wEntries, err := loadConfig()
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fatal configuration load failure: %v", err)
		os.Exit(1)
	}
	ctx.watchEntries = wEntries

	// Initialize fanotify channel
	fanFd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		logMsg(syslog.LOG_ERR, "Fanotify structural initialization failure: %v (Are you root?)", err)
		os.Exit(1)
	}
	defer unix.Close(fanFd)

	// Map watches onto security layer
	addAllMarks(fanFd, ctx.watchEntries)
	logMsg(syslog.LOG_INFO, "Daemon functional framework active. Enforcing strict structural baseline.")

	// === Signal Handling Setup ===
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	// Goroutine tasked entirely with handling system signaling
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				logMsg(syslog.LOG_INFO, "SIGHUP intercepted - updating active policies")

				// Purge historical structural targets
				_ = unix.FanotifyMark(fanFd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, "/")

				if newEntries, err := loadConfig(); err == nil {
					ctx.Lock()
					ctx.watchEntries = newEntries
					ctx.Unlock()

					addAllMarks(fanFd, newEntries)
					logMsg(syslog.LOG_INFO, "Dynamic structural configuration hot-reload complete")
				} else {
					logMsg(syslog.LOG_ERR, "Aborting policy hot-reload due to configuration errors: %v", err)
				}

			case syscall.SIGTERM, syscall.SIGINT:
				logMsg(syslog.LOG_INFO, "Termination request processed. Shutting down...")
				unix.Close(fanFd) // Explicitly breaks the blocking file read loop below
				os.Exit(0)
			}
		}
	}()

	// === Event Processing Loop ===
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
		// Safely process variable length fanotify payload stream arrays using compile-time size calculations
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

				// Synthesize and reply with verdict mapping
				resp := unix.FanotifyResponse{
					Fd:       ev.Fd,
					Response: response,
				}

				// Transform native struct object memory to byte array representation via unsafe bounds calculations
				respBytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), int(unsafe.Sizeof(resp)))
				if _, err := unix.Write(fanFd, respBytes); err != nil {
					logMsg(syslog.LOG_ERR, "Failed to dispatch intercept evaluation message back to kernel: %v", err)
				}
			}

			// Clean up the event's file descriptor provided by the kernel
			if ev.Fd >= 0 {
				unix.Close(int(ev.Fd))
			}

			offset += int(ev.Event_len)
		}
	}
}
