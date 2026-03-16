package hushspec

import (
	"os"
	"path/filepath"
	"testing"
)

func resetPanic() {
	DeactivatePanic()
}

func TestPanicActivateDeactivate(t *testing.T) {
	resetPanic()
	defer resetPanic()

	if IsPanicActive() {
		t.Fatal("expected panic to be inactive initially")
	}

	ActivatePanic()
	if !IsPanicActive() {
		t.Fatal("expected panic to be active after ActivatePanic()")
	}

	DeactivatePanic()
	if IsPanicActive() {
		t.Fatal("expected panic to be inactive after DeactivatePanic()")
	}
}

func TestPanicModeDeniesAll(t *testing.T) {
	resetPanic()
	defer resetPanic()

	ActivatePanic()

	spec := &HushSpec{HushSpecVersion: "0.1.0"}

	actionTypes := []string{
		"tool_call", "egress", "file_read", "file_write",
		"patch_apply", "shell_command", "computer_use", "unknown_action",
	}

	for _, actionType := range actionTypes {
		action := &EvaluationAction{
			Type:   actionType,
			Target: "anything",
		}
		result := Evaluate(spec, action)
		if result.Decision != DecisionDeny {
			t.Errorf("expected deny for action type %q, got %q", actionType, result.Decision)
		}
		if result.MatchedRule != "__hushspec_panic__" {
			t.Errorf("expected matched_rule '__hushspec_panic__', got %q", result.MatchedRule)
		}
		if result.Reason != "emergency panic mode is active" {
			t.Errorf("expected panic reason, got %q", result.Reason)
		}
	}
}

func TestDeactivateRestoresNormal(t *testing.T) {
	resetPanic()
	defer resetPanic()

	spec := &HushSpec{HushSpecVersion: "0.1.0"}
	action := &EvaluationAction{
		Type:   "tool_call",
		Target: "some_tool",
	}

	result := Evaluate(spec, action)
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow in normal mode, got %q", result.Decision)
	}

	ActivatePanic()
	result = Evaluate(spec, action)
	if result.Decision != DecisionDeny {
		t.Fatalf("expected deny in panic mode, got %q", result.Decision)
	}

	DeactivatePanic()
	result = Evaluate(spec, action)
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow after deactivation, got %q", result.Decision)
	}
}

func TestSentinelFileActivatesPanic(t *testing.T) {
	resetPanic()
	defer resetPanic()

	dir := t.TempDir()
	sentinel := filepath.Join(dir, ".hushspec_panic")

	if err := os.WriteFile(sentinel, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	if !CheckPanicSentinel(sentinel) {
		t.Fatal("expected CheckPanicSentinel to return true when file exists")
	}
	if !IsPanicActive() {
		t.Fatal("expected panic to be active after sentinel check")
	}
}

func TestSentinelFileMissingDoesNotActivate(t *testing.T) {
	resetPanic()
	defer resetPanic()

	sentinel := filepath.Join(t.TempDir(), "nonexistent")

	if CheckPanicSentinel(sentinel) {
		t.Fatal("expected CheckPanicSentinel to return false when file missing")
	}
	if IsPanicActive() {
		t.Fatal("expected panic to remain inactive when sentinel missing")
	}
}
