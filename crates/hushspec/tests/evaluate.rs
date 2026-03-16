use hushspec::{Decision, EvaluationAction, HushSpec, evaluate};

#[test]
fn input_inject_denies_unlisted_type() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: input-injection
rules:
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "input_inject".into(),
            target: Some("mouse".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.input_injection.allowed_types")
    );
}

#[test]
fn computer_use_respects_remote_desktop_channel_blocks() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: remote-desktop
rules:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions:
      - remote.clipboard
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "computer_use".into(),
            target: Some("remote.clipboard".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.remote_desktop_channels.clipboard")
    );
}
