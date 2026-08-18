package collectors

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// InstalledApp contains details about an application installed on the system
type InstalledApp struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher"`
	InstallLocation string `json:"install_location"`
}

// MatchStrategy defines how string comparison is performed during detection
type MatchStrategy int

const (
	MatchContains MatchStrategy = iota // Substring match (legacy / loose)
	MatchExact                         // Strict exact match (case-insensitive)
)

// AppQuery allows querying an installed application using strict multi-criteria criteria
type AppQuery struct {
	Name          string
	Publisher     string        // Optional: verify expected publisher (e.g., "Google LLC", "Microsoft Corporation")
	MatchStrategy MatchStrategy // Loose (Contains) or Strict (Exact)
	SystemOnly    bool          // If true, search HKLM only (ignores user-level HKCU installations)
}

// GetAppVersion searches the Windows Registry to find an application using loose string matching.
func GetAppVersion(appName string) (*InstalledApp, error) {
	return GetAppVersionByQuery(AppQuery{
		Name:          appName,
		MatchStrategy: MatchContains,
	})
}

// GetAppVersionStrict searches for an exact application name and optional expected publisher.
func GetAppVersionStrict(appName string, publisher string) (*InstalledApp, error) {
	return GetAppVersionByQuery(AppQuery{
		Name:          appName,
		Publisher:     publisher,
		MatchStrategy: MatchExact,
		SystemOnly:    true,
	})
}

// GetAppVersionByQuery evaluates application detection against specified query parameters.
func GetAppVersionByQuery(query AppQuery) (*InstalledApp, error) {
	registryLocations := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	// Only search user registry if SystemOnly is false
	if !query.SystemOnly {
		registryLocations = append(registryLocations, struct {
			root registry.Key
			path string
		}{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`})
	}

	for _, loc := range registryLocations {
		app, err := searchAppWithQuery(loc.root, loc.path, query)
		if err == nil && app != nil {
			return app, nil
		}
	}

	return nil, fmt.Errorf("application %q not found matching criteria (exact=%v, publisher=%q)",
		query.Name, query.MatchStrategy == MatchExact, query.Publisher)
}

// searchAppWithQuery scans registry subkeys and evaluates matching criteria.
func searchAppWithQuery(root registry.Key, basePath string, query AppQuery) (*InstalledApp, error) {
	k, err := registry.OpenKey(root, basePath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	targetName := strings.ToLower(query.Name)
	targetPublisher := strings.ToLower(query.Publisher)

	for _, sk := range subkeys {
		subKeyPath := basePath + `\` + sk
		subK, err := registry.OpenKey(root, subKeyPath, registry.READ)
		if err != nil {
			continue
		}

		displayName, _, errName := subK.GetStringValue("DisplayName")
		if errName != nil || displayName == "" {
			subK.Close()
			continue
		}

		currentName := strings.ToLower(displayName)
		nameMatches := false

		switch query.MatchStrategy {
		case MatchExact:
			nameMatches = (currentName == targetName)
		case MatchContains:
			nameMatches = strings.Contains(currentName, targetName)
		}

		if !nameMatches {
			subK.Close()
			continue
		}

		publisher, _, _ := subK.GetStringValue("Publisher")
		if targetPublisher != "" {
			currentPublisher := strings.ToLower(publisher)
			if !strings.Contains(currentPublisher, targetPublisher) {
				subK.Close()
				continue
			}
		}

		version, _, _ := subK.GetStringValue("DisplayVersion")
		location, _, _ := subK.GetStringValue("InstallLocation")

		subK.Close()

		return &InstalledApp{
			Name:            displayName,
			Version:         version,
			Publisher:       publisher,
			InstallLocation: location,
		}, nil
	}

	return nil, nil
}

// ListInstalledApps retrieves all installed applications from the Windows registry.
func ListInstalledApps() ([]InstalledApp, error) {
	registryLocations := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	var apps []InstalledApp
	seen := make(map[string]bool)

	for _, loc := range registryLocations {
		k, err := registry.OpenKey(loc.root, loc.path, registry.READ)
		if err != nil {
			continue
		}

		subkeys, err := k.ReadSubKeyNames(-1)
		if err != nil {
			k.Close()
			continue
		}

		for _, sk := range subkeys {
			subKeyPath := loc.path + `\` + sk
			subK, err := registry.OpenKey(loc.root, subKeyPath, registry.READ)
			if err != nil {
				continue
			}

			displayName, _, errName := subK.GetStringValue("DisplayName")
			if errName == nil && displayName != "" && !seen[displayName] {
				seen[displayName] = true
				version, _, _ := subK.GetStringValue("DisplayVersion")
				publisher, _, _ := subK.GetStringValue("Publisher")
				location, _, _ := subK.GetStringValue("InstallLocation")

				apps = append(apps, InstalledApp{
					Name:            displayName,
					Version:         version,
					Publisher:       publisher,
					InstallLocation: location,
				})
			}
			subK.Close()
		}
		k.Close()
	}

	return apps, nil
}

// String returns a readable representation of the application details
func (a *InstalledApp) String() string {
	return fmt.Sprintf("%s (Version: %s, Publisher: %s)", a.Name, a.Version, a.Publisher)
}
