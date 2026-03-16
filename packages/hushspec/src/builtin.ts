import YAML from 'yaml';
import type { HushSpec } from './schema.js';

export const BUILTIN_NAMES = [
  'default',
  'strict',
  'permissive',
  'ai-agent',
  'cicd',
  'remote-desktop',
] as const;

export type BuiltinName = (typeof BUILTIN_NAMES)[number];

const BUILTIN_RULESETS: Record<BuiltinName, string> = {
  default: `hushspec: "0.1.0"
name: default
description: Default security rules for AI agent execution

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/id_rsa*"
      - "**/id_ed25519*"
      - "**/id_ecdsa*"
      - "**/.aws/**"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gitconfig"
      - "**/.password-store/**"
      - "**/pass/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      - "**/AppData/Roaming/Microsoft/Credentials/**"
      - "**/AppData/Local/Microsoft/Credentials/**"
      - "**/AppData/Roaming/Microsoft/Vault/**"
      - "**/NTUSER.DAT"
      - "**/Windows/System32/config/SAM"
      - "**/Windows/System32/config/SECURITY"
      - "**/Windows/System32/config/SYSTEM"
    exceptions: []

  egress:
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      - "*.npmjs.org"
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
    block: []
    default: block

  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{48}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"
      - "**/*_test.*"
      - "**/*.test.*"

  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    require_balance: false
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\\\s_\\\\-]?(security|auth|ssl|tls)"
      - "(?i)skip[\\\\s_\\\\-]?(verify|validation|check)"
      - "(?i)rm\\\\s+-rf\\\\s+/"
      - "(?i)chmod\\\\s+777"

  tool_access:
    allow: []
    block:
      - shell_exec
      - run_command
      - raw_file_write
      - raw_file_delete
    require_confirmation:
      - file_write
      - file_delete
      - git_push
    default: allow
    max_args_size: 1048576
`,
  strict: `hushspec: "0.1.0"
name: strict
description: Strict security rules with minimal permissions

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/id_rsa*"
      - "**/id_ed25519*"
      - "**/id_ecdsa*"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gitconfig"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.password-store/**"
      - "**/pass/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      - "**/AppData/Roaming/Microsoft/Credentials/**"
      - "**/AppData/Local/Microsoft/Credentials/**"
      - "**/AppData/Roaming/Microsoft/Vault/**"
      - "**/NTUSER.DAT"
      - "**/NTUSER.DAT.*"
      - "**/Windows/System32/config/SAM"
      - "**/Windows/System32/config/SECURITY"
      - "**/Windows/System32/config/SYSTEM"
      - "**/AppData/Roaming/Microsoft/SystemCertificates/**"
      - "**/*.reg"
      - "**/.vault/**"
      - "**/.secrets/**"
      - "**/credentials/**"
      - "**/private/**"
    exceptions: []

  egress:
    allow: []
    block: []
    default: block

  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{48}"
        severity: critical
      - name: anthropic_key
        pattern: "sk-ant-[A-Za-z0-9\\\\-]{95}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: critical
      - name: npm_token
        pattern: "npm_[A-Za-z0-9]{36}"
        severity: critical
      - name: slack_token
        pattern: "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"
        severity: critical
      - name: generic_api_key
        pattern: "(?i)(api[_\\\\-]?key|apikey)\\\\s*[:=]\\\\s*[A-Za-z0-9]{32,}"
        severity: error
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

  patch_integrity:
    max_additions: 500
    max_deletions: 200
    require_balance: true
    max_imbalance_ratio: 5.0
    forbidden_patterns:
      - "(?i)disable[\\\\s_\\\\-]?(security|auth|ssl|tls)"
      - "(?i)skip[\\\\s_\\\\-]?(verify|validation|check)"
      - "(?i)rm\\\\s+-rf\\\\s+/"
      - "(?i)chmod\\\\s+777"
      - "(?i)eval\\\\s*\\\\("
      - "(?i)exec\\\\s*\\\\("
      - "(?i)reverse[_\\\\-]?shell"
      - "(?i)bind[_\\\\-]?shell"

  tool_access:
    allow:
      - read_file
      - list_directory
      - search
      - grep
    block: []
    require_confirmation: []
    default: block
    max_args_size: 524288
`,
  permissive: `hushspec: "0.1.0"
name: permissive
description: Permissive rules for development (use with caution)

rules:
  egress:
    allow:
      - "*"
    block: []
    default: allow

  patch_integrity:
    max_additions: 10000
    max_deletions: 5000
    require_balance: false
    max_imbalance_ratio: 50.0
`,
  'ai-agent': `hushspec: "0.1.0"
name: ai-agent
description: Security rules optimized for AI coding assistants

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/id_rsa*"
      - "**/id_ed25519*"
      - "**/id_ecdsa*"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gitconfig"
      - "**/.gnupg/**"
      - "**/.kube/**"
      - "**/.docker/**"
      - "**/.npmrc"
      - "**/.password-store/**"
      - "**/pass/**"
      - "**/.1password/**"
      - "/etc/shadow"
      - "/etc/passwd"
      - "/etc/sudoers"
      - "**/AppData/Roaming/Microsoft/Credentials/**"
      - "**/AppData/Local/Microsoft/Credentials/**"
      - "**/AppData/Roaming/Microsoft/Vault/**"
      - "**/NTUSER.DAT"
      - "**/Windows/System32/config/SAM"
      - "**/Windows/System32/config/SECURITY"
      - "**/Windows/System32/config/SYSTEM"
    exceptions:
      - "**/.env.example"
      - "**/.env.template"

  egress:
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "api.together.xyz"
      - "api.fireworks.ai"
      - "api.github.com"
      - "github.com"
      - "*.githubusercontent.com"
      - "gitlab.com"
      - "bitbucket.org"
      - "*.npmjs.org"
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
    block: []
    default: block

  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{48}"
        severity: critical
      - name: anthropic_key
        pattern: "sk-ant-[A-Za-z0-9\\\\-]{95}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"
      - "**/fixtures/**"
      - "**/mocks/**"

  patch_integrity:
    max_additions: 2000
    max_deletions: 1000
    require_balance: false
    max_imbalance_ratio: 20.0
    forbidden_patterns:
      - "(?i)rm\\\\s+-rf\\\\s+/"
      - "(?i)chmod\\\\s+777"

  shell_commands:
    forbidden_patterns:
      - "(?i)rm\\\\s+-rf\\\\s+/"
      - "curl.*\\\\|.*bash"
      - "wget.*\\\\|.*bash"

  tool_access:
    allow: []
    block:
      - shell_exec
      - run_command
    require_confirmation:
      - git_push
      - deploy
      - publish
    default: allow
    max_args_size: 2097152
`,
  cicd: `hushspec: "0.1.0"
name: cicd
description: Security rules for CI/CD pipelines

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "**/.git-credentials"
      - "**/.gnupg/**"
      - "**/.github/secrets/**"
      - "**/.gitlab-ci-secrets/**"
      - "**/.circleci/secrets/**"
    exceptions:
      - "**/.github/workflows/**"
      - "**/.gitlab-ci.yml"
      - "**/.circleci/config.yml"

  egress:
    allow:
      - "*.npmjs.org"
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
      - "static.crates.io"
      - "rubygems.org"
      - "packagist.org"
      - "plugins.gradle.org"
      - "*.docker.io"
      - "*.docker.com"
      - "*.gcr.io"
      - "*.ecr.aws"
      - "ghcr.io"
      - "repo1.maven.org"
      - "services.gradle.org"
    block: []
    default: block

  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

  tool_access:
    allow:
      - read_file
      - write_file
      - list_directory
      - run_tests
      - build
    block:
      - shell_exec
      - deploy_production
    default: block
`,
  'remote-desktop': `hushspec: "0.1.0"
name: remote-desktop
description: Security rules for remote desktop and computer use agent sessions

rules:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - remote.session.connect
      - remote.session.disconnect
      - remote.session.reconnect
      - input.inject
      - remote.clipboard
      - remote.file_transfer
      - remote.audio
      - remote.drive_mapping
      - remote.printing
      - remote.session_share

  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false

  input_injection:
    enabled: true
    allowed_types:
      - keyboard
      - mouse
    require_postcondition_probe: false
`,
};

/**
 * Parsed directly with YAML.parse (no regex validation) because builtins
 * may contain RE2/PCRE patterns like `(?i)` that aren't valid JS regex.
 */
export function loadBuiltin(name: string): HushSpec | null {
  const resolved = name.startsWith('builtin:') ? name.slice(8) : name;

  if (!(BUILTIN_NAMES as readonly string[]).includes(resolved)) {
    return null;
  }

  const yaml = BUILTIN_RULESETS[resolved as BuiltinName];
  const doc = YAML.parse(yaml) as HushSpec;
  if (!doc || typeof doc !== 'object' || !doc.hushspec) {
    return null;
  }
  return doc;
}
