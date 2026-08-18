package test

//!: Demo test showing policy loading and evaluation against collectors

import (
	"fmt"
	"testing"

	"github.com/pallandos/nano-zt/internal/collectors"
	"github.com/pallandos/nano-zt/internal/evaluator"
)

func TestEvaluator(t *testing.T) {
	// 1. Load configuration policy
	configPath := "../config/config.yml"
	policy, err := evaluator.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load policy configuration: %s\n", err)
	}

	fmt.Printf("Loaded policy: %s (v%s)\n", policy.Name, policy.Version)

	// 2. Gather measurements from collectors
	osVer, _ := collectors.GetOSVersion()
	avHealth, _ := collectors.GetGlobalAntivirusHealth()
	fwHealth, _ := collectors.GetGlobalFirewallHealth()

	chromeApp, _ := collectors.GetAppVersion("Chrome")
	var installedApps []collectors.InstalledApp
	if chromeApp != nil {
		installedApps = append(installedApps, *chromeApp)
	}

	// 3. Evaluate measurements against policy rules
	result := evaluator.Evaluate(policy, osVer, avHealth, fwHealth, installedApps)

	fmt.Printf("Evaluation Passed: %t\n", result.Passed)
	fmt.Printf("Total Violations: %d\n", len(result.Violations))

	for i, v := range result.Violations {
		fmt.Printf("  [%d] [%s] [%s] %s: %s\n", i+1, v.Severity, v.Category, v.Rule, v.Message)
	}
}
