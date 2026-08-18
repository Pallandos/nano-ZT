package evaluator

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PolicyWrapper represents the top-level YAML root key "policy"
type PolicyWrapper struct {
	Policy PolicyConfig `yaml:"policy"`
}

// PolicyConfig contains all evaluation rules for collectors
type PolicyConfig struct {
	Name         string              `yaml:"name"`
	Version      string              `yaml:"version"`
	OSVersion    OSVersionPolicy     `yaml:"os_version"`
	Security     SecurityPolicy      `yaml:"security"`
	Applications []ApplicationPolicy `yaml:"applications"`
}

// OSVersionPolicy defines evaluation criteria for Windows OS version
type OSVersionPolicy struct {
	Enabled                bool     `yaml:"enabled"`
	MinMajor               uint64   `yaml:"min_major"`
	MinMinor               uint64   `yaml:"min_minor"`
	MinUBR                 uint64   `yaml:"min_ubr"`
	AllowedDisplayVersions []string `yaml:"allowed_display_versions"`
	ExcludedBuilds         []string `yaml:"excluded_builds"`
}

// SecurityPolicy wraps WSC provider policies (Antivirus and Firewall)
type SecurityPolicy struct {
	Antivirus SecurityProviderPolicy `yaml:"antivirus"`
	Firewall  SecurityProviderPolicy `yaml:"firewall"`
}

// SecurityProviderPolicy defines evaluation criteria for WSC security health
type SecurityProviderPolicy struct {
	Enabled            bool     `yaml:"enabled"`
	RequireHealthy     bool     `yaml:"require_healthy"`
	AllowedStatuses    []string `yaml:"allowed_statuses"`
	DisallowedStatuses []string `yaml:"disallowed_statuses"`
}

// ApplicationPolicy defines criteria for an individual application
type ApplicationPolicy struct {
	Name              string   `yaml:"name"`
	Enabled           bool     `yaml:"enabled"`
	Disallowed        bool     `yaml:"disallowed"`        // Must NOT be installed
	RequireInstalled  bool     `yaml:"require_installed"` // MUST be installed
	MinVersion        string   `yaml:"min_version"`       // Minimum version threshold
	MaxVersion        string   `yaml:"max_version"`       // Maximum version threshold
	ExactVersion      string   `yaml:"exact_version"`     // Required exact version
	AllowedVersions   []string `yaml:"allowed_versions"`  // Whitelist of allowed versions
	ExcludedVersions  []string `yaml:"excluded_versions"` // Blacklist of prohibited versions
	ExpectedPublisher string   `yaml:"expected_publisher"`
	RequireSigned     bool     `yaml:"require_signed"`    // Must have valid Authenticode signature
	AllowedSHA256     []string `yaml:"allowed_sha256"`    // Whitelist of trusted binary hashes
}

// LoadConfig parses a YAML configuration file and returns a PolicyConfig
func LoadConfig(filePath string) (*PolicyConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy config file: %w", err)
	}

	var wrapper PolicyWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	return &wrapper.Policy, nil
}
