package collectors

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Constants from wscapi.h (windows doc)
const (
	WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x4

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

// Global state of protection
type AVHealth struct {
	IsHealthy   bool
	Status      string
	Description string
}

func GetGlobalAntivirusHealth() (*AVHealth, error) {
	var health uint32

	// System call
	ret, _, errSys := procWscGetSecurityProviderHealth.Call(
		uintptr(WSC_SECURITY_PROVIDER_ANTIVIRUS),
		uintptr(unsafe.Pointer(&health)), // Pointer
	)

	if ret != 0 {
		return nil, fmt.Errorf("Fail to call API (HRESULT: 0x%x). System error: %v", ret, errSys)
	}

	result := &AVHealth{}

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
