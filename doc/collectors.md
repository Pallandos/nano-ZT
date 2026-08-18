# Collectors

Collectors are components responsible for collecting system informations for the agent. Results are stored in a go `struct`, which are described below. 

## Antivirus

Result type returned by the collector: 

```go
type AVHealth struct {
	IsHealthy   bool
	Status      string
	Description string
}
```

Possible values for `Status` are `"GOOD"`, `"NOT_MONITORED"`, `"POOR"`, `"SNOOZE"` or `"UNKNOWN"`. For `Description`, refer to [this](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider_health).

## OS version

This collector gets the SemVer informations relative to the OS. 

```go
type OSVersion struct {
	Major          uint64 `json:"major"`
	Minor          uint64 `json:"minor"`
	Build          string `json:"build"`
	UBR            uint64 `json:"ubr"`             // Update Build Revision  (security patch)
	DisplayVersion string `json:"display_version"` // Commercial name (ex: 22H2, 23H2)
}
```

For example, the collector will return : 

    10.0.26200.8875 (25H2)

## App version

This collector returns information about any installed app, such as version and publisher. 

```go
type InstalledApp struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher"`
	InstallLocation string `json:"install_location"`
}
```