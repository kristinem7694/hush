use clap::ValueEnum;
use colored::Colorize;
use hushspec::{HushSpec, validate_governance};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct AuditArgs {
    /// Policy YAML file to audit
    #[arg(required = true)]
    file: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct AuditReport {
    file: String,
    name: Option<String>,
    author: Option<String>,
    approved_by: Option<String>,
    approval_date: Option<String>,
    classification: Option<String>,
    lifecycle_state: Option<String>,
    policy_version: Option<usize>,
    change_ticket: Option<String>,
    effective_date: Option<String>,
    expiry_date: Option<String>,
    checks: Vec<AuditCheck>,
}

#[derive(serde::Serialize)]
struct AuditCheck {
    name: String,
    passed: bool,
    detail: Option<String>,
}

pub fn run(args: AuditArgs) -> i32 {
    if !args.file.exists() {
        eprintln!(
            "{} file not found: {}",
            "\u{2717}".red(),
            args.file.display()
        );
        return 2;
    }

    let content = match std::fs::read_to_string(&args.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} failed to read file: {}", "\u{2717}".red(), e);
            return 2;
        }
    };

    let spec = match HushSpec::parse(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} YAML parse error: {}", "\u{2717}".red(), e);
            return 1;
        }
    };

    let governance_warnings = validate_governance(&spec);
    let warning_codes: Vec<&str> = governance_warnings
        .iter()
        .map(|w| w.code.as_str())
        .collect();

    let metadata = spec.metadata.as_ref();

    let author = metadata.and_then(|m| m.author.clone());
    let approved_by = metadata.and_then(|m| m.approved_by.clone());
    let approval_date = metadata.and_then(|m| m.approval_date.clone());
    let classification = metadata.and_then(|m| {
        m.classification.as_ref().and_then(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
        })
    });
    let lifecycle_state = metadata.and_then(|m| {
        m.lifecycle_state.as_ref().and_then(|s| {
            serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
        })
    });
    let policy_version = metadata.and_then(|m| m.policy_version);
    let change_ticket = metadata.and_then(|m| m.change_ticket.clone());
    let effective_date = metadata.and_then(|m| m.effective_date.clone());
    let expiry_date = metadata.and_then(|m| m.expiry_date.clone());

    let mut checks = Vec::new();

    checks.push(AuditCheck {
        name: "Has author".into(),
        passed: author.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Has approver".into(),
        passed: approved_by.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Has approval date".into(),
        passed: approval_date.is_some(),
        detail: if warning_codes.contains(&"GOV_MISSING_APPROVAL_DATE") {
            Some("approved_by set without approval_date".into())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Classification set".into(),
        passed: classification.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Lifecycle state set".into(),
        passed: lifecycle_state.is_some(),
        detail: if warning_codes.contains(&"GOV_LIFECYCLE") {
            governance_warnings
                .iter()
                .find(|w| w.code == "GOV_LIFECYCLE")
                .map(|w| w.message.clone())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Policy version set".into(),
        passed: policy_version.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Expiry date set".into(),
        passed: expiry_date.is_some(),
        detail: if warning_codes.contains(&"GOV_EXPIRED") {
            governance_warnings
                .iter()
                .find(|w| w.code == "GOV_EXPIRED")
                .map(|w| w.message.clone())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Restricted approval check".into(),
        passed: !warning_codes.contains(&"GOV_RESTRICTED_NO_APPROVER"),
        detail: if warning_codes.contains(&"GOV_RESTRICTED_NO_APPROVER") {
            Some("restricted classification requires approved_by".into())
        } else {
            None
        },
    });

    let report = AuditReport {
        file: args.file.display().to_string(),
        name: spec.name.clone(),
        author,
        approved_by,
        approval_date,
        classification,
        lifecycle_state,
        policy_version,
        change_ticket,
        effective_date,
        expiry_date,
        checks,
    };

    match args.format {
        OutputFormat::Text => print_text_report(&report),
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{json}");
            }
        }
    }

    // Governance is advisory -- always exit 0 regardless of check outcomes.
    0
}

fn print_text_report(report: &AuditReport) {
    println!(
        "{}  {}",
        "Policy:".bold(),
        report.name.as_deref().unwrap_or("(unnamed)")
    );

    fn print_field(label: &str, value: &Option<String>) {
        if let Some(v) = value {
            println!("{}  {}", format!("{label}:").bold(), v);
        }
    }

    print_field("Author", &report.author);
    print_field("Approved by", &report.approved_by);
    print_field("Approval date", &report.approval_date);
    print_field("Classification", &report.classification);
    print_field("Lifecycle", &report.lifecycle_state);
    print_field(
        "Policy version",
        &report.policy_version.map(|v| v.to_string()),
    );
    print_field("Change ticket", &report.change_ticket);
    print_field("Effective date", &report.effective_date);
    print_field("Expiry date", &report.expiry_date);

    println!();
    println!("{}", "Governance checks:".bold());
    for check in &report.checks {
        if check.passed {
            print!("  {} {}", "\u{2713}".green(), check.name);
        } else {
            print!("  {} {}", "\u{2717}".red(), check.name);
        }
        if let Some(detail) = &check.detail {
            print!(" ({})", detail.yellow());
        }
        println!();
    }
}
