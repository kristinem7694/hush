package hushspec

import (
	"os"
	"sync/atomic"
)

var panicActive atomic.Bool

// ActivatePanic enables global panic mode. All Evaluate calls will deny.
func ActivatePanic() {
	panicActive.Store(true)
}

// DeactivatePanic disables panic mode, restoring normal evaluation.
func DeactivatePanic() {
	panicActive.Store(false)
}

func IsPanicActive() bool {
	return panicActive.Load()
}

// CheckPanicSentinel activates panic mode if the file at path exists.
func CheckPanicSentinel(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		ActivatePanic()
		return true
	}
	return false
}
