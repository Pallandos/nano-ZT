package collectors

// This module uses the WSC security provider feature to collect informations relative to
// security providers registered to Windows like firewall, AV, UAC ...

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Constants from wscapi.h (windows doc)
const (
	WSC_SECURITY_PROVIDER_FIREWALL             = 0x1
	WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS  = 0x2
	WSC_SECURITY_PROVIDER_ANTIVIRUS            = 0x4
	WSC_SECURITY_PROVIDER_ANTISPYWARE          = 0x8
	WSC_SECURITY_PROVIDER_INTERNET_SETTINGS    = 0x10
	WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 0x20
	WSC_SECURITY_PROVIDER_SERVICE              = 0x40

	WSC_SECURITY_PROVIDER_HEALTH_GOOD         = 0
	WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED = 1
	WSC_SECURITY_PROVIDER_HEALTH_POOR         = 2
	WSC_SECURITY_PROVIDER_HEALTH_SNOOZE       = 3
)

var (
	// Lazy loading of the dll
	modwscapi = windows.NewLazySystemDLL("wscapi.dll")
	// Load specific function
	procWscGetSecurityProviderHealth = modwscapi.NewProc("WscGetSecurityProviderHealth")
)

// SecurityHealth represents the global state of a generic protection provider
type SecurityHealth struct {
	IsHealthy   bool
	Status      string
	Description string
}

// Generic internal function (non exported)
func getSecurityProviderHealth(provider uint32) (*SecurityHealth, error) {
	var health uint32

	// System call
	ret, _, errSys := procWscGetSecurityProviderHealth.Call(
		uintptr(provider),
		uintptr(unsafe.Pointer(&health)), // Pointer
	)

	if ret != 0 {
		return nil, fmt.Errorf("fail to call API (HRESULT: 0x%x). System error: %v", ret, errSys)
	}

	result := &SecurityHealth{}

	// Get and interpret result
	switch health {
	case WSC_SECURITY_PROVIDER_HEALTH_GOOD:
		result.IsHealthy = true
		result.Status = "GOOD"
		result.Description = "The status of the security provider category is good and does not need user attention."
	case WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED:
		result.IsHealthy = false
		result.Status = "NOT_MONITORED"
		result.Description = "The status of the security provider category is not monitored by WSC."
	case WSC_SECURITY_PROVIDER_HEALTH_POOR:
		result.IsHealthy = false
		result.Status = "POOR"
		result.Description = "The status of the security provider category is poor and the computer may be at risk."
	case WSC_SECURITY_PROVIDER_HEALTH_SNOOZE:
		result.IsHealthy = false
		result.Status = "SNOOZE"
		result.Description = "The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer."
	default:
		result.IsHealthy = false
		result.Status = "UNKNOWN"
		result.Description = fmt.Sprintf("Unknown state : %d", health)
	}

	return result, nil
}

// GetGlobalAntivirusHealth checks the Antivirus status
func GetGlobalAntivirusHealth() (*SecurityHealth, error) {
	return getSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)
}

// GetGlobalFirewallHealth checks the Firewall status
func GetGlobalFirewallHealth() (*SecurityHealth, error) {
	return getSecurityProviderHealth(WSC_SECURITY_PROVIDER_FIREWALL)
}

//?: maybe check if a specific AV is installed and running
