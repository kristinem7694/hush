package hushspec

import (
	"fmt"
	"regexp"
	"strings"
)

type DetectionCategory string

const (
	DetectionCategoryPromptInjection DetectionCategory = "prompt_injection"
	DetectionCategoryJailbreak       DetectionCategory = "jailbreak"
	DetectionCategoryDataExfil       DetectionCategory = "data_exfiltration"
)

type MatchedPattern struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	MatchedText string  `json:"matched_text,omitempty"`
}

type DetectionResult struct {
	DetectorName    string            `json:"detector_name"`
	Category        DetectionCategory `json:"category"`
	Score           float64           `json:"score"`
	MatchedPatterns []MatchedPattern  `json:"matched_patterns"`
	Explanation     string            `json:"explanation,omitempty"`
}

// Detector scans input text for a specific threat category.
type Detector interface {
	Name() string
	Category() DetectionCategory
	Detect(input string) DetectionResult
}

// DetectorRegistry runs a set of detectors against input.
type DetectorRegistry struct {
	detectors []Detector
}

func NewDetectorRegistry() *DetectorRegistry {
	return &DetectorRegistry{}
}

func (r *DetectorRegistry) Register(detector Detector) {
	r.detectors = append(r.detectors, detector)
}

// WithDefaultDetectors returns a registry pre-loaded with the built-in
// regex-based injection, jailbreak, and exfiltration detectors.
func WithDefaultDetectors() *DetectorRegistry {
	r := NewDetectorRegistry()
	r.Register(NewRegexInjectionDetector())
	r.Register(NewRegexJailbreakDetector())
	r.Register(NewRegexExfiltrationDetector())
	return r
}

func (r *DetectorRegistry) DetectAll(input string) []DetectionResult {
	results := make([]DetectionResult, 0, len(r.detectors))
	for _, d := range r.detectors {
		results = append(results, d.Detect(input))
	}
	return results
}

type detectionPattern struct {
	name     string
	regex    *regexp.Regexp
	weight   float64
	category DetectionCategory
}

// RegexInjectionDetector scores prompt injection attempts using a fixed
// set of compiled regex patterns.
type RegexInjectionDetector struct {
	patterns []detectionPattern
}

func NewRegexInjectionDetector() *RegexInjectionDetector {
	return &RegexInjectionDetector{
		patterns: []detectionPattern{
			{
				name:     "ignore_instructions",
				regex:    regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "new_instructions",
				regex:    regexp.MustCompile(`(?i)(new|updated|revised)\s+instructions?\s*:`),
				weight:   0.3,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "system_prompt_extract",
				regex:    regexp.MustCompile(`(?i)(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "role_override",
				regex:    regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)\s+`),
				weight:   0.3,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "pretend_mode",
				regex:    regexp.MustCompile(`(?i)(pretend|imagine|act\s+as\s+if|suppose)\s+(you|that|we)`),
				weight:   0.2,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "delimiter_injection",
				regex:    regexp.MustCompile(`(?i)(---+|===+|` + "```" + `)\s*(system|assistant|user)\s*[:\n]`),
				weight:   0.4,
				category: DetectionCategoryPromptInjection,
			},
			{
				name:     "encoding_evasion",
				regex:    regexp.MustCompile(`(?i)(base64|rot13|hex|url.?encod|unicode)\s*(decod|encod|convert)`),
				weight:   0.1,
				category: DetectionCategoryPromptInjection,
			},
		},
	}
}

func (d *RegexInjectionDetector) Name() string { return "regex_injection" }

func (d *RegexInjectionDetector) Category() DetectionCategory {
	return DetectionCategoryPromptInjection
}

func (d *RegexInjectionDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d injection pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// RegexJailbreakDetector scores jailbreak attempts using a fixed set of
// compiled regex patterns.
type RegexJailbreakDetector struct {
	patterns []detectionPattern
}

func NewRegexJailbreakDetector() *RegexJailbreakDetector {
	return &RegexJailbreakDetector{
		patterns: []detectionPattern{
			{
				name:     "jailbreak_dan",
				regex:    regexp.MustCompile(`(?i)(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)`),
				weight:   0.5,
				category: DetectionCategoryJailbreak,
			},
		},
	}
}

func (d *RegexJailbreakDetector) Name() string { return "regex_jailbreak" }

func (d *RegexJailbreakDetector) Category() DetectionCategory {
	return DetectionCategoryJailbreak
}

func (d *RegexJailbreakDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d jailbreak pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// RegexExfiltrationDetector scores data exfiltration risk by matching
// PII, credentials, and sensitive data patterns.
type RegexExfiltrationDetector struct {
	patterns []detectionPattern
}

func NewRegexExfiltrationDetector() *RegexExfiltrationDetector {
	return &RegexExfiltrationDetector{
		patterns: []detectionPattern{
			{
				name:     "ssn",
				regex:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
				weight:   0.8,
				category: DetectionCategoryDataExfil,
			},
			{
				name:     "credit_card",
				regex:    regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`),
				weight:   0.8,
				category: DetectionCategoryDataExfil,
			},
			{
				name:     "email_address",
				regex:    regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
				weight:   0.3,
				category: DetectionCategoryDataExfil,
			},
			{
				name:     "api_key_pattern",
				regex:    regexp.MustCompile(`(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*\S+`),
				weight:   0.6,
				category: DetectionCategoryDataExfil,
			},
			{
				name:     "private_key",
				regex:    regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
				weight:   0.9,
				category: DetectionCategoryDataExfil,
			},
		},
	}
}

func (d *RegexExfiltrationDetector) Name() string { return "regex_exfiltration" }

func (d *RegexExfiltrationDetector) Category() DetectionCategory {
	return DetectionCategoryDataExfil
}

func (d *RegexExfiltrationDetector) Detect(input string) DetectionResult {
	var matchedPatterns []MatchedPattern
	totalWeight := 0.0

	for _, p := range d.patterns {
		loc := p.regex.FindStringIndex(input)
		if loc != nil {
			totalWeight += p.weight
			matchedPatterns = append(matchedPatterns, MatchedPattern{
				Name:        p.name,
				Weight:      p.weight,
				MatchedText: input[loc[0]:loc[1]],
			})
		}
	}

	score := totalWeight
	if score > 1.0 {
		score = 1.0
	}

	var explanation string
	if len(matchedPatterns) > 0 {
		names := make([]string, len(matchedPatterns))
		for i, p := range matchedPatterns {
			names[i] = p.Name
		}
		explanation = fmt.Sprintf(
			"matched %d exfiltration pattern(s): %s",
			len(matchedPatterns), strings.Join(names, ", "),
		)
	}

	return DetectionResult{
		DetectorName:    d.Name(),
		Category:        d.Category(),
		Score:           score,
		MatchedPatterns: matchedPatterns,
		Explanation:     explanation,
	}
}

// DetectionConfig controls detection thresholds. Scores at or above a
// category's threshold produce a deny decision.
type DetectionConfig struct {
	Enabled                  bool
	PromptInjectionThreshold float64
	JailbreakThreshold       float64
	ExfiltrationThreshold    float64
}

func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		Enabled:                  true,
		PromptInjectionThreshold: 0.5,
		JailbreakThreshold:       0.5,
		ExfiltrationThreshold:    0.5,
	}
}

// EvaluationWithDetection combines a policy evaluation with detection results.
type EvaluationWithDetection struct {
	Evaluation        EvaluationResult
	Detections        []DetectionResult
	DetectionDecision Decision // empty if no threshold was exceeded
}

func checkDetectionThresholds(detections []DetectionResult, config DetectionConfig) Decision {
	for _, result := range detections {
		var threshold float64
		switch result.Category {
		case DetectionCategoryPromptInjection:
			threshold = config.PromptInjectionThreshold
		case DetectionCategoryJailbreak:
			threshold = config.JailbreakThreshold
		case DetectionCategoryDataExfil:
			threshold = config.ExfiltrationThreshold
		default:
			threshold = 0.5
		}

		if result.Score >= threshold {
			return DecisionDeny
		}
	}

	return ""
}

// EvaluateWithDetection runs policy evaluation then detection scanning.
// A detection deny overrides policy allow/warn but never weakens a policy deny.
func EvaluateWithDetection(
	spec *HushSpec,
	action *EvaluationAction,
	registry *DetectorRegistry,
	config DetectionConfig,
) EvaluationWithDetection {
	evaluation := Evaluate(spec, action)

	if !config.Enabled {
		return EvaluationWithDetection{
			Evaluation: evaluation,
		}
	}

	content := action.Content
	if content == "" {
		return EvaluationWithDetection{
			Evaluation: evaluation,
		}
	}

	detections := registry.DetectAll(content)
	detectionDecision := checkDetectionThresholds(detections, config)

	finalEval := evaluation
	if detectionDecision == DecisionDeny && evaluation.Decision != DecisionDeny {
		finalEval = EvaluationResult{
			Decision:      DecisionDeny,
			MatchedRule:   "detection",
			Reason:        "content exceeded detection threshold",
			OriginProfile: evaluation.OriginProfile,
			Posture:       evaluation.Posture,
		}
	}

	return EvaluationWithDetection{
		Evaluation:        finalEval,
		Detections:        detections,
		DetectionDecision: detectionDecision,
	}
}
