package ludusapi

import (
	"os"
	"sync/atomic"
)

const (
	processRoleDefault int32 = 0 // Defer to os.Geteuid() == 0 (legacy systemd behavior)
	processRoleUser    int32 = 1 // Explicit user-facing API server (:8080)
	processRoleAdmin   int32 = 2 // Explicit admin API server (127.0.0.1:8081)
)

var activeProcessRole atomic.Int32

// SetAdminProcess explicitly configures whether this process acts as the
// ludus-admin server (127.0.0.1:8081) or the user-facing ludus server (:8080),
// allowing both processes to run unprivileged (e.g. UID 1000) in container mode.
func SetAdminProcess(isAdmin bool) {
	if isAdmin {
		activeProcessRole.Store(processRoleAdmin)
		return
	}
	activeProcessRole.Store(processRoleUser)
}

// ResetProcessRole restores default UID-based process role detection.
func ResetProcessRole() {
	activeProcessRole.Store(processRoleDefault)
}

// IsAdminProcess reports whether the current process is serving the privileged
// ludus-admin API role. When SetAdminProcess has not been called explicitly,
// it preserves legacy behavior (os.Geteuid() == 0).
func IsAdminProcess() bool {
	switch activeProcessRole.Load() {
	case processRoleAdmin:
		return true
	case processRoleUser:
		return false
	default:
		return os.Geteuid() == 0
	}
}
