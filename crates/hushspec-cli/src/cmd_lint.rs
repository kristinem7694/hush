use clap::ValueEnum;
use colored::Colorize;
use hushspec::evaluate::glob_matches;
use hushspec::{DefaultAction, HushSpec};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct LintArgs {
    /// Policy YAML files to lint
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: LintOutputFormat,

    /// Exit 1 if any warnings are reported (not just errors)
    #[arg(long)]
    fail_on_warnings: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LintOutputFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, serde::Serialize)]
struct LintFinding {
    code: String,
    severity: String,
    message: String,
    location: String,
}

#[derive(serde::Serialize)]
struct FileLintResult {
    file: String,
    findings: Vec<LintFinding>,
}

pub fn run(args: LintArgs) -> i32 {
    let mut all_results: Vec<FileLintResult> = Vec::new();
    let mut any_errors = false;
    let mut any_warnings = false;
    let mut any_parse_error = false;

    for path in &args.files {
        if !path.exists() {
            if matches!(args.format, LintOutputFormat::Text) {
                eprintln!("{} file not found: {}", "error".red(), path.display());
            }
            all_results.push(FileLintResult {
                file: path.display().to_string(),
                findings: vec![LintFinding {
                    code: "E000".into(),
                    severity: "error".into(),
                    message: format!("file not found: {}", path.display()),
                    location: path.display().to_string(),
                }],
            });
            any_parse_error = true;
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} failed to read {}: {e}", "error".red(), path.display());
                }
                all_results.push(FileLintResult {
                    file: path.display().to_string(),
                    findings: vec![LintFinding {
                        code: "E000".into(),
                        severity: "error".into(),
                        message: format!("failed to read file: {e}"),
                        location: path.display().to_string(),
                    }],
                });
                any_parse_error = true;
                continue;
            }
        };

        let spec = match HushSpec::parse(&content) {
            Ok(s) => s,
            Err(e) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} failed to parse {}: {e}", "error".red(), path.display());
                }
                all_results.push(FileLintResult {
                    file: path.display().to_string(),
                    findings: vec![LintFinding {
                        code: "E001".into(),
                        severity: "error".into(),
                        message: format!("YAML parse error: {e}"),
                        location: path.display().to_string(),
                    }],
                });
                any_parse_error = true;
                continue;
            }
        };

        let findings = lint_spec(&spec, &path.display().to_string());

        for f in &findings {
            match f.severity.as_str() {
                "error" => any_errors = true,
                "warning" => any_warnings = true,
                _ => {}
            }
        }

        if matches!(args.format, LintOutputFormat::Text) {
            print_text_findings(&findings, &path.display().to_string());
        }

        all_results.push(FileLintResult {
            file: path.display().to_string(),
            findings,
        });
    }

    if matches!(args.format, LintOutputFormat::Json)
        && let Ok(json) = serde_json::to_string_pretty(&all_results)
    {
        println!("{json}");
    }

    if any_parse_error || any_errors || (any_warnings && args.fail_on_warnings) {
        1
    } else {
        0
    }
}

fn print_text_findings(findings: &[LintFinding], _file: &str) {
    for f in findings {
        let severity_colored = match f.severity.as_str() {
            "error" => format!("error[{}]", f.code).red().to_string(),
            "warning" => format!("warning[{}]", f.code).yellow().to_string(),
            _ => format!("info[{}]", f.code).cyan().to_string(),
        };
        println!("{}: {}", severity_colored, f.message);
        println!("  {} {}", "-->".dimmed(), f.location);
        println!();
    }
}

fn lint_spec(spec: &HushSpec, file: &str) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    let Some(rules) = &spec.rules else {
        return findings;
    };

    // L001: empty-rule-block
    check_empty_rule_blocks(rules, file, &mut findings);

    // L002: overlapping-patterns
    check_overlapping_patterns(rules, file, &mut findings);

    // L003: shadowed-exception
    check_shadowed_exceptions(rules, file, &mut findings);

    // L004: overly-broad-egress
    check_overly_broad_egress(rules, file, &mut findings);

    // L005: empty blocklist with default allow
    check_empty_blocklist_with_default_allow(rules, file, &mut findings);

    // L006: regex-complexity
    check_regex_complexity(rules, file, &mut findings);

    // L007: disabled-rule
    check_disabled_rules(rules, file, &mut findings);

    // L008: duplicate-patterns
    check_duplicate_patterns(rules, file, &mut findings);

    // L009: missing-secret-patterns
    check_missing_secret_patterns(rules, file, &mut findings);

    // L010: unreachable-allow
    check_unreachable_allow(rules, file, &mut findings);

    findings
}

fn check_empty_rule_blocks(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && egress.allow.is_empty()
        && egress.block.is_empty()
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message:
                "rules.egress has no allow or block entries and default is allow -- rule block has no effect"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && tool_access.allow.is_empty()
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
        && tool_access.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message:
                "rules.tool_access has no allow, block, or require_confirmation entries and default is allow -- rule block has no effect"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(forbidden_paths) = &rules.forbidden_paths
        && forbidden_paths.enabled
        && forbidden_paths.patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.forbidden_paths has no patterns -- rule block has no effect".into(),
            location: file.into(),
        });
    }

    if let Some(shell_commands) = &rules.shell_commands
        && shell_commands.enabled
        && shell_commands.forbidden_patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.shell_commands has no forbidden_patterns -- rule block has no effect"
                .into(),
            location: file.into(),
        });
    }

    if let Some(secret_patterns) = &rules.secret_patterns
        && secret_patterns.enabled
        && secret_patterns.patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.secret_patterns has no patterns -- rule block has no effect".into(),
            location: file.into(),
        });
    }
}

fn check_overlapping_patterns(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(forbidden_paths) = &rules.forbidden_paths {
        find_overlapping_globs(
            &forbidden_paths.patterns,
            "rules.forbidden_paths.patterns",
            file,
            findings,
        );
    }

    if let Some(egress) = &rules.egress {
        find_overlapping_globs(&egress.allow, "rules.egress.allow", file, findings);
        find_overlapping_globs(&egress.block, "rules.egress.block", file, findings);
    }

    if let Some(tool_access) = &rules.tool_access {
        find_overlapping_globs(
            &tool_access.allow,
            "rules.tool_access.allow",
            file,
            findings,
        );
        find_overlapping_globs(
            &tool_access.block,
            "rules.tool_access.block",
            file,
            findings,
        );
    }
}

fn find_overlapping_globs(
    patterns: &[String],
    path: &str,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    for i in 0..patterns.len() {
        for j in (i + 1)..patterns.len() {
            if globs_may_overlap(&patterns[i], &patterns[j]) {
                findings.push(LintFinding {
                    code: "L002".into(),
                    severity: "warning".into(),
                    message: format!(
                        "{path}[{i}] {:?} and {path}[{j}] {:?} may overlap",
                        patterns[i], patterns[j]
                    ),
                    location: file.into(),
                });
            }
        }
    }
}

/// Heuristic check: do two glob patterns potentially match the same target?
fn globs_may_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }

    let test_paths = generate_synthetic_paths(a)
        .into_iter()
        .chain(generate_synthetic_paths(b));

    for path in test_paths {
        if glob_matches(a, &path) && glob_matches(b, &path) {
            return true;
        }
    }

    false
}

/// Generate synthetic test paths from a glob pattern by extracting literal segments
fn generate_synthetic_paths(pattern: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let stripped = pattern.replace("**", "/synthetic").replace('*', "example");

    paths.push(stripped.clone());

    let alt = pattern.replace("**", "/home/user").replace('*', "test");
    if alt != stripped {
        paths.push(alt);
    }

    let dotvar = pattern.replace("**", "/app").replace('*', "file.txt");
    if dotvar != stripped {
        paths.push(dotvar);
    }

    paths
}

fn check_shadowed_exceptions(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    let Some(forbidden_paths) = &rules.forbidden_paths else {
        return;
    };

    if forbidden_paths.patterns.is_empty() {
        return;
    }

    for (i, exception) in forbidden_paths.exceptions.iter().enumerate() {
        let synthetic = generate_synthetic_paths(exception);
        let any_blocked = synthetic.iter().any(|test_path| {
            forbidden_paths
                .patterns
                .iter()
                .any(|pattern| glob_matches(pattern, test_path))
        });

        if !any_blocked {
            findings.push(LintFinding {
                code: "L003".into(),
                severity: "warning".into(),
                message: format!(
                    "rules.forbidden_paths.exceptions[{i}] {:?} does not match any forbidden pattern -- exception has no effect",
                    exception
                ),
                location: file.into(),
            });
        }
    }
}

fn check_overly_broad_egress(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        for (i, pattern) in egress.allow.iter().enumerate() {
            if pattern == "*" || pattern == "*.*" {
                findings.push(LintFinding {
                    code: "L004".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.egress.allow[{i}] contains wildcard pattern {:?} -- this allows all egress, making the rule ineffective",
                        pattern
                    ),
                    location: file.into(),
                });
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        for (i, pattern) in tool_access.allow.iter().enumerate() {
            if pattern == "*" {
                findings.push(LintFinding {
                    code: "L004".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.tool_access.allow[{i}] contains wildcard pattern {:?} -- this allows all tools, making the rule ineffective",
                        pattern
                    ),
                    location: file.into(),
                });
            }
        }
    }
}

fn check_empty_blocklist_with_default_allow(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && !egress.allow.is_empty()
        && egress.block.is_empty()
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L005".into(),
            severity: "info".into(),
            message:
                "rules.egress has default \"allow\" with an empty block list -- all egress is permitted regardless of the allow list"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && !tool_access.allow.is_empty()
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
        && tool_access.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L005".into(),
            severity: "info".into(),
            message:
                "rules.tool_access has default \"allow\" with empty block and require_confirmation lists -- all tools are permitted regardless of the allow list"
                    .into(),
            location: file.into(),
        });
    }
}

fn check_regex_complexity(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        for (i, pat) in secret_patterns.patterns.iter().enumerate() {
            check_single_regex(
                &pat.pattern,
                &format!("rules.secret_patterns.patterns[{i}]"),
                file,
                findings,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        for (i, pat) in shell_commands.forbidden_patterns.iter().enumerate() {
            check_single_regex(
                pat,
                &format!("rules.shell_commands.forbidden_patterns[{i}]"),
                file,
                findings,
            );
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        for (i, pat) in patch_integrity.forbidden_patterns.iter().enumerate() {
            check_single_regex(
                pat,
                &format!("rules.patch_integrity.forbidden_patterns[{i}]"),
                file,
                findings,
            );
        }
    }
}

fn check_single_regex(pattern: &str, path: &str, file: &str, findings: &mut Vec<LintFinding>) {
    let mut reasons = Vec::new();

    if pattern.len() > 200 {
        reasons.push("pattern exceeds 200 characters");
    }

    let alternation_count = pattern.matches('|').count();
    if alternation_count > 5 {
        reasons.push("pattern has more than 5 alternations");
    }

    if has_nested_quantifiers(pattern) {
        reasons.push("pattern has nested quantifiers (potential ReDoS risk)");
    }

    if !reasons.is_empty() {
        findings.push(LintFinding {
            code: "L006".into(),
            severity: "warning".into(),
            message: format!("{path}: regex complexity warning -- {}", reasons.join("; ")),
            location: file.into(),
        });
    }
}

/// Heuristic detection of nested quantifiers that could cause ReDoS
fn has_nested_quantifiers(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut depth = 0;
    let mut has_inner_quantifier = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'(' => {
                depth += 1;
                has_inner_quantifier = false;
            }
            b')' => {
                if depth > 0 {
                    depth -= 1;
                    if has_inner_quantifier
                        && i + 1 < bytes.len()
                        && matches!(bytes[i + 1], b'+' | b'*' | b'{')
                    {
                        return true;
                    }
                }
                has_inner_quantifier = false;
            }
            b'+' | b'*' => {
                if depth > 0 {
                    has_inner_quantifier = true;
                }
            }
            _ => {}
        }
        i += 1;
    }

    false
}

fn check_disabled_rules(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    let disabled_checks: &[(&str, Option<bool>)] = &[
        (
            "rules.forbidden_paths",
            rules.forbidden_paths.as_ref().map(|r| r.enabled),
        ),
        ("rules.egress", rules.egress.as_ref().map(|r| r.enabled)),
        (
            "rules.secret_patterns",
            rules.secret_patterns.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.shell_commands",
            rules.shell_commands.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.tool_access",
            rules.tool_access.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.patch_integrity",
            rules.patch_integrity.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.computer_use",
            rules.computer_use.as_ref().map(|r| r.enabled),
        ),
    ];

    for &(name, enabled) in disabled_checks {
        if enabled == Some(false) {
            findings.push(LintFinding {
                code: "L007".into(),
                severity: "info".into(),
                message: format!("{name} is explicitly disabled"),
                location: file.into(),
            });
        }
    }
}

fn check_duplicate_patterns(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(forbidden_paths) = &rules.forbidden_paths {
        find_duplicates(
            &forbidden_paths.patterns,
            "rules.forbidden_paths.patterns",
            file,
            findings,
        );
        find_duplicates(
            &forbidden_paths.exceptions,
            "rules.forbidden_paths.exceptions",
            file,
            findings,
        );
    }

    if let Some(egress) = &rules.egress {
        find_duplicates(&egress.allow, "rules.egress.allow", file, findings);
        find_duplicates(&egress.block, "rules.egress.block", file, findings);
    }

    if let Some(tool_access) = &rules.tool_access {
        find_duplicates(
            &tool_access.allow,
            "rules.tool_access.allow",
            file,
            findings,
        );
        find_duplicates(
            &tool_access.block,
            "rules.tool_access.block",
            file,
            findings,
        );
        find_duplicates(
            &tool_access.require_confirmation,
            "rules.tool_access.require_confirmation",
            file,
            findings,
        );
    }

    if let Some(shell_commands) = &rules.shell_commands {
        find_duplicates(
            &shell_commands.forbidden_patterns,
            "rules.shell_commands.forbidden_patterns",
            file,
            findings,
        );
    }
}

fn find_duplicates(list: &[String], path: &str, file: &str, findings: &mut Vec<LintFinding>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for (i, entry) in list.iter().enumerate() {
        if !seen.insert(entry.as_str()) {
            findings.push(LintFinding {
                code: "L008".into(),
                severity: "warning".into(),
                message: format!("{path}[{i}]: duplicate pattern {:?}", entry),
                location: file.into(),
            });
        }
    }
}

fn check_missing_secret_patterns(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if rules.secret_patterns.is_none() {
        findings.push(LintFinding {
            code: "L009".into(),
            severity: "info".into(),
            message: "policy has no secret_patterns rule -- consider adding secret detection for file_write operations".into(),
            location: file.into(),
        });
    }
}

fn check_unreachable_allow(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        let block_set: HashSet<&str> = egress.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in egress.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding {
                    code: "L010".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.egress.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    location: file.into(),
                });
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        let block_set: HashSet<&str> = tool_access.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in tool_access.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding {
                    code: "L010".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.tool_access.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    location: file.into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_nested_quantifiers() {
        assert!(has_nested_quantifiers("(a+)+"));
        assert!(has_nested_quantifiers("(.*a)+"));
        assert!(has_nested_quantifiers("([a-z]+)*"));
        assert!(!has_nested_quantifiers("a+b+c+"));
        assert!(!has_nested_quantifiers("[a-z]+"));
        assert!(!has_nested_quantifiers("(abc)"));
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("*.txt", "hello.txt"));
        assert!(!glob_matches("*.txt", "hello.rs"));
        assert!(glob_matches("**/.ssh/**", "/home/user/.ssh/id_rsa"));
        assert!(glob_matches("*", "anything"));
    }
}
