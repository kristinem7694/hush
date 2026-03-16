package hushspec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidRegexPatternsPass(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "aws_key", Pattern: "AKIA[0-9A-Z]{16}", Severity: SeverityCritical},
					{Name: "private_key", Pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----", Severity: SeverityCritical},
				},
			},
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{"(?i)rm\\s+-rf\\s+/", "curl.*\\|.*bash"},
			},
			PatchIntegrity: &PatchIntegrityRule{
				Enabled:           true,
				MaxImbalanceRatio: floatPtr(10.0),
				ForbiddenPatterns: []string{"(?i)disable[\\s_\\-]?(security|auth|ssl|tls)", "(?i)chmod\\s+777"},
			},
		},
	}
	result := Validate(spec)
	if !result.IsValid() {
		t.Fatalf("expected valid RE2 patterns to pass validation, got errors: %+v", result.Errors)
	}
}

func TestInvalidRegexSyntaxSecretPatterns(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "bad", Pattern: "[unterminated", Severity: SeverityCritical},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected invalid regex syntax to fail validation")
	}
	found := false
	for _, err := range result.Errors {
		if err.Code == "INVALID_REGEX" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected INVALID_REGEX error code, got: %+v", result.Errors)
	}
}

func TestInvalidRegexSyntaxShellCommands(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{"[invalid"},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected invalid regex in shell_commands to fail validation")
	}
}

func TestInvalidRegexSyntaxPatchIntegrity(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			PatchIntegrity: &PatchIntegrityRule{
				Enabled:           true,
				MaxImbalanceRatio: floatPtr(10.0),
				ForbiddenPatterns: []string{"valid_pattern", "(unclosed"},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected invalid regex in patch_integrity to fail validation")
	}
}

func TestGoRegexpRejectsBackreference(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "backref", Pattern: "(a)\\1", Severity: SeverityCritical},
				},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected backreference pattern to be rejected by Go regexp (RE2)")
	}
}

func TestGoRegexpRejectsLookahead(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{"(?=foo)bar"},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected lookahead pattern to be rejected by Go regexp (RE2)")
	}
}

func TestGoRegexpRejectsLookbehind(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			PatchIntegrity: &PatchIntegrityRule{
				Enabled:           true,
				MaxImbalanceRatio: floatPtr(10.0),
				ForbiddenPatterns: []string{"(?<=password:)\\s*\\S+"},
			},
		},
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected lookbehind pattern to be rejected by Go regexp (RE2)")
	}
}

func TestBuiltInRulesetsPassValidation(t *testing.T) {
	rulesetDir := filepath.Join("..", "..", "..", "rulesets")
	rulesetFiles := []string{
		"default.yaml",
		"strict.yaml",
		"permissive.yaml",
		"ai-agent.yaml",
		"cicd.yaml",
		"remote-desktop.yaml",
	}

	for _, filename := range rulesetFiles {
		t.Run(filename, func(t *testing.T) {
			path := filepath.Join(rulesetDir, filename)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read ruleset %s: %v", filename, err)
			}
			spec, parseErr := Parse(string(data))
			if parseErr != nil {
				t.Fatalf("ruleset %s failed to parse: %v", filename, parseErr)
			}
			result := Validate(spec)
			if !result.IsValid() {
				t.Fatalf("ruleset %s failed validation: %+v", filename, result.Errors)
			}
		})
	}
}

func floatPtr(f float64) *float64 {
	return &f
}
