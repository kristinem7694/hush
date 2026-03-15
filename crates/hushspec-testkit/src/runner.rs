use crate::fixture::{FixtureCategory, TestFixture};
use hushspec::HushSpec;

#[derive(Debug, Clone)]
pub struct TestResult {
    pub fixture_path: String,
    pub category: FixtureCategory,
    pub passed: bool,
    pub message: String,
}

/// Run conformance tests for all fixtures.
pub fn run_conformance(fixtures: &[TestFixture]) -> Vec<TestResult> {
    let mut results = Vec::new();

    for fixture in fixtures {
        let result = match fixture.category {
            FixtureCategory::ValidCore
            | FixtureCategory::PostureValid
            | FixtureCategory::OriginsValid
            | FixtureCategory::DetectionValid => test_valid_fixture(fixture),

            FixtureCategory::InvalidCore
            | FixtureCategory::PostureInvalid
            | FixtureCategory::OriginsInvalid
            | FixtureCategory::DetectionInvalid => test_invalid_fixture(fixture),

            FixtureCategory::Evaluation => test_evaluation_fixture(fixture),

            FixtureCategory::MergeBase
            | FixtureCategory::MergeChild
            | FixtureCategory::MergeExpected => {
                // Skip individual merge files; merge tests are handled as groups
                continue;
            }
        };
        results.push(result);
    }

    results
}

fn test_valid_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    match HushSpec::parse(&fixture.content) {
        Ok(spec) => {
            let validation = hushspec::validate(&spec);
            if validation.is_valid() {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: true,
                    message: "OK".to_string(),
                }
            } else {
                let errors: Vec<String> =
                    validation.errors.iter().map(|e| e.to_string()).collect();
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: false,
                    message: format!("Validation failed: {}", errors.join(", ")),
                }
            }
        }
        Err(e) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!("Parse failed: {e}"),
        },
    }
}

fn test_invalid_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    match HushSpec::parse(&fixture.content) {
        Ok(spec) => {
            let validation = hushspec::validate(&spec);
            if validation.is_valid() {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: false,
                    message: "Expected rejection but document was accepted".to_string(),
                }
            } else {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: true,
                    message: format!("Correctly rejected: {}", validation.errors[0]),
                }
            }
        }
        Err(_) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: true,
            message: "Correctly rejected at parse time".to_string(),
        },
    }
}

fn test_evaluation_fixture(fixture: &TestFixture) -> TestResult {
    // Evaluation fixtures just need to parse (the test cases inside are engine-specific)
    let path = fixture.path.display().to_string();
    // Try to parse as a generic YAML to at least validate structure
    match serde_yaml::from_str::<serde_yaml::Value>(&fixture.content) {
        Ok(_) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: true,
            message: "OK (evaluation fixture parseable)".to_string(),
        },
        Err(e) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!("Invalid YAML: {e}"),
        },
    }
}
