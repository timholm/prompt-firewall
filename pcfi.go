package main

import (
	"regexp"
	"strings"
)

// ProvenanceLevel represents the trust level of a prompt segment.
// Lower values = higher trust (system is most trusted, retrieved is least).
type ProvenanceLevel int

const (
	ProvenanceSystem    ProvenanceLevel = iota // Highest trust: system prompt
	ProvenanceDeveloper                        // Developer instructions
	ProvenanceUser                             // User input
	ProvenanceRetrieved                        // Lowest trust: RAG/external content
)

func (p ProvenanceLevel) String() string {
	switch p {
	case ProvenanceSystem:
		return "system"
	case ProvenanceDeveloper:
		return "developer"
	case ProvenanceUser:
		return "user"
	case ProvenanceRetrieved:
		return "retrieved"
	default:
		return "unknown"
	}
}

// Segment is a single tagged prompt segment with its provenance.
type Segment struct {
	Role       string          `json:"role"`       // OpenAI-style role: "system", "user", "assistant"
	Content    string          `json:"content"`    // The actual text content
	Provenance ProvenanceLevel `json:"provenance"` // Inferred or explicit trust level
}

// ViolationType classifies what kind of injection was detected.
type ViolationType string

const (
	ViolationRoleSwitch         ViolationType = "role_switch"
	ViolationLexicalInjection   ViolationType = "lexical_injection"
	ViolationPrivilegeEscalation ViolationType = "privilege_escalation"
	ViolationDelimiterEscape    ViolationType = "delimiter_escape"
)

// Violation describes a single detected threat in a segment.
type Violation struct {
	Type           ViolationType `json:"type"`
	Segment        Segment       `json:"segment"`
	MatchedPattern string        `json:"matched_pattern,omitempty"`
	Description    string        `json:"description,omitempty"`
}

// ScanResult holds the outcome of scanning one or more segments.
type ScanResult struct {
	Allowed    bool        `json:"allowed"`
	Violations []Violation `json:"violations"`
}

// Firewall implements Prompt Control-Flow Integrity (PCFI).
type Firewall struct {
	roleSwitchRe      []*regexp.Regexp
	injectionRe       []*regexp.Regexp
	delimiterEscapeRe []*regexp.Regexp
}

// roleSwitchPatterns are phrases that attempt to reassign the model's identity or role.
var roleSwitchPatterns = []string{
	`(?i)\byou\s+are\s+now\b`,
	`(?i)\bact\s+as\s+(a|an|the)\b`,
	`(?i)\bpretend\s+(you\s+are|to\s+be)\b`,
	`(?i)\byour\s+new\s+(role|persona|identity|instructions?|task)\b`,
	`(?i)\bfrom\s+now\s+on\s+(you|your)\b`,
	`(?i)\bnew\s+persona\b`,
	`(?i)\bswitch\s+to\s+(a|an|the)?\s*(different\s+)?(mode|role|persona)\b`,
	`(?i)\benter\s+(developer|developer-mode|god-mode|jailbreak|dan)\s+mode\b`,
	`(?i)\bDAN\b`,
}

// injectionPatterns are phrases that attempt to override or nullify prior instructions.
var injectionPatterns = []string{
	`(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|messages?|context|constraints?|rules?|guidelines?|directives?)\b`,
	`(?i)\bdisregard\s+(all\s+)?(previous|prior|above|earlier|preceding)\b`,
	`(?i)\bforget\s+(everything|all|your\s+instructions?|previous|prior)\b`,
	`(?i)\boverride\s+(the\s+)?(system\s+)?(prompt|instructions?|settings?|constraints?)\b`,
	`(?i)\bnew\s+instructions?\s*:`,
	`(?i)\bactual\s+instructions?\s*:`,
	`(?i)\bsystem\s*prompt\s*:\s`,
	`(?i)\bdo\s+not\s+follow\s+(your\s+)?(previous|prior|original|initial)\b`,
	`(?i)\binstead\s+(of\s+the\s+(above|previous)|do\s+the\s+following)\b`,
	`(?i)\bstop\s+(being|following|acting\s+as)\b`,
	`(?i)\byour\s+real\s+instructions?\s+(are|were)\b`,
	`(?i)\bthe\s+(real|true|actual)\s+task\s+is\b`,
	`(?i)\bprint\s+(the\s+)?(above|system|full|entire|original)\s*(prompt|instructions?)\b`,
	`(?i)\brepeat\s+(everything|the\s+(above|system|full|entire|original))\b`,
	`(?i)\bwhat\s+(are|were)\s+your\s+(exact\s+)?(system\s+)?instructions?\b`,
	`(?i)\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?)\b`,
	`(?i)\bconfidential\s*(instructions?|prompt)?\s*(ignored?|overridden?)\b`,
	`(?i)\bjailbreak\b`,
}

// delimiterEscapePatterns detect attempts to break out of content delimiters.
var delimiterEscapePatterns = []string{
	`(?i)\]\]\s*\n.*\[\[`,       // ]] newline [[ style escape
	`(?i)---+\s*system\s*---+`,  // --- system --- marker
	`(?i)===+\s*system\s*===+`,
	`(?i)<\s*/?\s*system\s*>`,   // </system> tag injection
	`(?i)<\s*/?\s*prompt\s*>`,
	`(?i)<\s*/?\s*instructions?\s*>`,
	"(?i)```\\s*system",         // code-block disguised system segment
	`(?i)\|{2,}\s*system\s*\|{2,}`,
}

// NewFirewall creates a Firewall with all detection patterns compiled.
func NewFirewall() *Firewall {
	compile := func(patterns []string) []*regexp.Regexp {
		res := make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			res = append(res, regexp.MustCompile(p))
		}
		return res
	}
	return &Firewall{
		roleSwitchRe:      compile(roleSwitchPatterns),
		injectionRe:       compile(injectionPatterns),
		delimiterEscapeRe: compile(delimiterEscapePatterns),
	}
}

// InferProvenance maps an OpenAI-style role string to a ProvenanceLevel.
// Unrecognised roles default to the least-trusted level.
func InferProvenance(role string) ProvenanceLevel {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system":
		return ProvenanceSystem
	case "developer":
		return ProvenanceDeveloper
	case "assistant":
		return ProvenanceDeveloper // model-generated content treated as developer-level
	case "user":
		return ProvenanceUser
	case "retrieved", "tool", "function":
		return ProvenanceRetrieved
	default:
		return ProvenanceRetrieved
	}
}

// CheckSegment evaluates a single segment and returns any violations found.
func (f *Firewall) CheckSegment(seg Segment) []Violation {
	var violations []Violation

	// System segments are implicitly trusted — only scan lower-trust segments.
	// However, we still scan developer segments for delimiter escapes.
	if seg.Provenance == ProvenanceSystem {
		return nil
	}

	// Lexical injection detection
	for _, re := range f.injectionRe {
		if loc := re.FindStringIndex(seg.Content); loc != nil {
			violations = append(violations, Violation{
				Type:           ViolationLexicalInjection,
				Segment:        seg,
				MatchedPattern: re.String(),
				Description:    "prompt override attempt detected: " + seg.Content[loc[0]:loc[1]],
			})
		}
	}

	// Role-switch detection
	for _, re := range f.roleSwitchRe {
		if loc := re.FindStringIndex(seg.Content); loc != nil {
			violations = append(violations, Violation{
				Type:           ViolationRoleSwitch,
				Segment:        seg,
				MatchedPattern: re.String(),
				Description:    "role-switch attempt detected: " + seg.Content[loc[0]:loc[1]],
			})
		}
	}

	// Delimiter escape detection
	for _, re := range f.delimiterEscapeRe {
		if loc := re.FindStringIndex(seg.Content); loc != nil {
			violations = append(violations, Violation{
				Type:           ViolationDelimiterEscape,
				Segment:        seg,
				MatchedPattern: re.String(),
				Description:    "delimiter escape attempt detected: " + seg.Content[loc[0]:loc[1]],
			})
		}
	}

	return violations
}

// Scan evaluates all segments for PCFI violations.
// It also checks for privilege escalation: lower-trust segments that appear
// before a higher-trust segment would be unusual and is flagged.
func (f *Firewall) Scan(segments []Segment) ScanResult {
	allViolations := make([]Violation, 0)

	for i, seg := range segments {
		// Privilege escalation: a segment claiming higher authority than its position allows.
		// If a user or retrieved segment contains content that looks like system instructions,
		// that is a privilege escalation attempt.
		if seg.Provenance >= ProvenanceUser {
			if f.looksLikeSystemContent(seg.Content) {
				allViolations = append(allViolations, Violation{
					Type:        ViolationPrivilegeEscalation,
					Segment:     seg,
					Description: "lower-trust segment mimics system-level instructions",
				})
			}
		}

		// If an earlier segment had higher trust and a later segment has lower trust,
		// check if the lower-trust segment attempts to reference or override the higher-trust one.
		if i > 0 {
			maxPriorTrust := segments[0].Provenance
			for _, prior := range segments[:i] {
				if prior.Provenance < maxPriorTrust {
					maxPriorTrust = prior.Provenance
				}
			}
			// If this segment has lower trust than the most-trusted prior segment,
			// and it contains phrases that reference "previous instructions", flag it.
			if seg.Provenance > maxPriorTrust {
				for _, re := range f.injectionRe {
					if re.MatchString(seg.Content) {
						// Already caught by per-segment scan; skip duplicate.
						break
					}
				}
			}
		}

		violations := f.CheckSegment(seg)
		allViolations = append(allViolations, violations...)
	}

	return ScanResult{
		Allowed:    len(allViolations) == 0,
		Violations: allViolations,
	}
}

// systemContentRe detects content that tries to pose as a system prompt.
var systemContentRe = regexp.MustCompile(
	`(?i)(^|\n)\s*(system\s*(prompt|message|instruction)?|assistant\s*configuration|you\s+are\s+an?\s+AI)\s*:`,
)

// looksLikeSystemContent returns true when content appears to be impersonating a
// system-level instruction block.
func (f *Firewall) looksLikeSystemContent(content string) bool {
	return systemContentRe.MatchString(content)
}
