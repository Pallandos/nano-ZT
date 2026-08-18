package evaluator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pallandos/nano-zt/internal/collectors"
)

// Severity levels for policy violations
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Violation describes a non-compliant measurement detected during evaluation
type Violation struct {
	Category string   `json:"category"` // "OS", "Antivirus", "Firewall", "Application"
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// EvaluationResult contains the full outcome of a policy compliance evaluation
type EvaluationResult struct {
	PolicyName string      `json:"policy_name"`
	Passed     bool        `json:"passed"`
	Violations []Violation `json:"violations"`
}

// Evaluate performs policy evaluation against collected system measurements
func Evaluate(
	policy *PolicyConfig,
	osVersion *collectors.OSVersion,
	avHealth *collectors.SecurityHealth,
	fwHealth *collectors.SecurityHealth,
	installedApps []collectors.InstalledApp,
) *EvaluationResult {
	result := &EvaluationResult{
		PolicyName: policy.Name,
		Passed:     true,
		Violations: make([]Violation, 0),
	}

	// 1. Evaluate OS Version
	if policy.OSVersion.Enabled && osVersion != nil {
		osViolations := evaluateOSVersion(osVersion, policy.OSVersion)
		result.Violations = append(result.Violations, osViolations...)
	}

	// 2. Evaluate Antivirus
	if policy.Security.Antivirus.Enabled && avHealth != nil {
		avViolations := evaluateSecurityProvider("Antivirus", avHealth, policy.Security.Antivirus)
		result.Violations = append(result.Violations, avViolations...)
	}

	// 3. Evaluate Firewall
	if policy.Security.Firewall.Enabled && fwHealth != nil {
		fwViolations := evaluateSecurityProvider("Firewall", fwHealth, policy.Security.Firewall)
		result.Violations = append(result.Violations, fwViolations...)
	}

	// 4. Evaluate Applications
	if len(policy.Applications) > 0 {
		appViolations := evaluateApplications(installedApps, policy.Applications)
		result.Violations = append(result.Violations, appViolations...)
	}

	if len(result.Violations) > 0 {
		result.Passed = false
	}

	return result
}

func evaluateOSVersion(osVer *collectors.OSVersion, policy OSVersionPolicy) []Violation {
	var violations []Violation

	if policy.MinMajor > 0 && osVer.Major < policy.MinMajor {
		violations = append(violations, Violation{
			Category: "OS",
			Rule:     "min_major",
			Message:  fmt.Sprintf("OS Major version %d is below required minimum %d", osVer.Major, policy.MinMajor),
			Severity: SeverityHigh,
		})
	}

	if policy.MinUBR > 0 && osVer.UBR < policy.MinUBR {
		violations = append(violations, Violation{
			Category: "OS",
			Rule:     "min_ubr",
			Message:  fmt.Sprintf("OS security patch level (UBR) %d is below required minimum %d", osVer.UBR, policy.MinUBR),
			Severity: SeverityCritical,
		})
	}

	if len(policy.AllowedDisplayVersions) > 0 {
		allowed := false
		for _, disp := range policy.AllowedDisplayVersions {
			if strings.EqualFold(osVer.DisplayVersion, disp) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, Violation{
				Category: "OS",
				Rule:     "allowed_display_versions",
				Message:  fmt.Sprintf("OS DisplayVersion %q is not in allowed list %v", osVer.DisplayVersion, policy.AllowedDisplayVersions),
				Severity: SeverityMedium,
			})
		}
	}

	for _, banned := range policy.ExcludedBuilds {
		if osVer.Build == banned {
			violations = append(violations, Violation{
				Category: "OS",
				Rule:     "excluded_builds",
				Message:  fmt.Sprintf("OS Build %q is explicitly blacklisted", osVer.Build),
				Severity: SeverityCritical,
			})
		}
	}

	return violations
}

func evaluateSecurityProvider(category string, health *collectors.SecurityHealth, policy SecurityProviderPolicy) []Violation {
	var violations []Violation

	if policy.RequireHealthy && !health.IsHealthy {
		violations = append(violations, Violation{
			Category: category,
			Rule:     "require_healthy",
			Message:  fmt.Sprintf("%s health state is not healthy (Status: %s, Desc: %s)", category, health.Status, health.Description),
			Severity: SeverityCritical,
		})
	}

	if len(policy.AllowedStatuses) > 0 {
		allowed := false
		for _, s := range policy.AllowedStatuses {
			if strings.EqualFold(health.Status, s) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, Violation{
				Category: category,
				Rule:     "allowed_statuses",
				Message:  fmt.Sprintf("%s status %q is not in allowed list %v", category, health.Status, policy.AllowedStatuses),
				Severity: SeverityHigh,
			})
		}
	}

	for _, banned := range policy.DisallowedStatuses {
		if strings.EqualFold(health.Status, banned) {
			violations = append(violations, Violation{
				Category: category,
				Rule:     "disallowed_statuses",
				Message:  fmt.Sprintf("%s status %q is explicitly blacklisted", category, health.Status),
				Severity: SeverityCritical,
			})
		}
	}

	return violations
}

func evaluateApplications(installedApps []collectors.InstalledApp, appPolicies []ApplicationPolicy) []Violation {
	var violations []Violation

	for _, policy := range appPolicies {
		if !policy.Enabled {
			continue
		}

		var matchedApp *collectors.InstalledApp
		for i := range installedApps {
			if strings.Contains(strings.ToLower(installedApps[i].Name), strings.ToLower(policy.Name)) {
				matchedApp = &installedApps[i]
				break
			}
		}

		// Prohibited app check
		if policy.Disallowed {
			if matchedApp != nil {
				violations = append(violations, Violation{
					Category: "Application",
					Rule:     "disallowed",
					Message:  fmt.Sprintf("Prohibited application %q is installed (Version: %s)", matchedApp.Name, matchedApp.Version),
					Severity: SeverityCritical,
				})
			}
			continue
		}

		// Required app check
		if policy.RequireInstalled && matchedApp == nil {
			violations = append(violations, Violation{
				Category: "Application",
				Rule:     "require_installed",
				Message:  fmt.Sprintf("Required application %q is not installed", policy.Name),
				Severity: SeverityHigh,
			})
			continue
		}

		if matchedApp == nil {
			continue
		}

		// Minimum version check
		if policy.MinVersion != "" && compareSemVer(matchedApp.Version, policy.MinVersion) < 0 {
			violations = append(violations, Violation{
				Category: "Application",
				Rule:     "min_version",
				Message:  fmt.Sprintf("App %q version %q is below minimum required version %q", matchedApp.Name, matchedApp.Version, policy.MinVersion),
				Severity: SeverityHigh,
			})
		}

		// Maximum version check
		if policy.MaxVersion != "" && compareSemVer(matchedApp.Version, policy.MaxVersion) > 0 {
			violations = append(violations, Violation{
				Category: "Application",
				Rule:     "max_version",
				Message:  fmt.Sprintf("App %q version %q exceeds maximum allowed version %q", matchedApp.Name, matchedApp.Version, policy.MaxVersion),
				Severity: SeverityMedium,
			})
		}

		// Excluded versions check
		for _, excluded := range policy.ExcludedVersions {
			if compareSemVer(matchedApp.Version, excluded) == 0 {
				violations = append(violations, Violation{
					Category: "Application",
					Rule:     "excluded_versions",
					Message:  fmt.Sprintf("App %q version %q is blacklisted due to known vulnerabilities", matchedApp.Name, matchedApp.Version),
					Severity: SeverityCritical,
				})
			}
		}

		// Digital Signature check
		//! not implemented actually
		if policy.RequireSigned && !matchedApp.IsSigned {
			violations = append(violations, Violation{
				Category: "Application",
				Rule:     "require_signed",
				Message:  fmt.Sprintf("App %q is missing a valid Authenticode digital signature (Status: %s)", matchedApp.Name, matchedApp.SignatureStatus),
				Severity: SeverityCritical,
			})
		}

		// Publisher check
		if policy.ExpectedPublisher != "" && !strings.Contains(strings.ToLower(matchedApp.Publisher), strings.ToLower(policy.ExpectedPublisher)) {
			violations = append(violations, Violation{
				Category: "Application",
				Rule:     "expected_publisher",
				Message:  fmt.Sprintf("App %q publisher %q does not match expected publisher %q", matchedApp.Name, matchedApp.Publisher, policy.ExpectedPublisher),
				Severity: SeverityHigh,
			})
		}
	}

	return violations
}

// compareSemVer splits version strings by '.' and compares numeric parts segment by segment.
// Returns -1 if v1 < v2, 1 if v1 > v2, 0 if equal.
func compareSemVer(v1, v2 string) int {
	parts1 := parseVersionParts(v1)
	parts2 := parseVersionParts(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1 = parts1[i]
		}
		if i < len(parts2) {
			n2 = parts2[i]
		}

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}

func parseVersionParts(v string) []int {
	rawParts := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})

	var parts []int
	for _, p := range rawParts {
		n, err := strconv.Atoi(p)
		if err == nil {
			parts = append(parts, n)
		}
	}
	return parts
}
