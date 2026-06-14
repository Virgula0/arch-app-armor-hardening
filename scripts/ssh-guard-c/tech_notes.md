### Ssh-guard.c notes

The identity check in `is_allowed`() uses open("/proc/PID/exe", O_PATH) followed by `fstat()` on that file descriptor rather than readlink + stat. The `O_PATH` flag is important: it opens a reference to the kernel's dentry for the binary without reading or executing anything, and the kernel holds that reference across the `fstat()` call. This makes it TOCTOU-resistant --- if an attacker races to replace the binary between the readlink and the stat, we still get the inode of what the kernel believes is running, not what's on disk at that moment.

On `SIGHUP`, the daemon calls `fanotify_mark(fd, FAN_MARK_FLUSH, ...)` which atomically removes all inode marks, then re-adds them after re-reading the config. Pending permission events already in the kernel queue are answered with the old whitelist before the flush, so there's no window where legitimate access is dropped mid-operation.

The `FAN_EVENT_ON_CHILD` flag on the directory mark is what generates events for files inside `~/.ssh` --- without it, only the directory inode itself would be covered. Since `~/.ssh` is typically flat (no subdirs), this covers all key files and config.
