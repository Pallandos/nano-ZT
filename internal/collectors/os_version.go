package collectors

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// OSVersion contains SemVEr informations
type OSVersion struct {
	Major          uint64 `json:"major"`
	Minor          uint64 `json:"minor"`
	Build          string `json:"build"`
	UBR            uint64 `json:"ubr"`             // Update Build Revision  (security patch)
	DisplayVersion string `json:"display_version"` // Commercial name (ex: 22H2, 23H2)
}

func GetOSVersion() (*OSVersion, error) {
	// Path of Windows Version
	path := `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

	// Open in RO mode
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("Unable to open registry key : %w", err)
	}
	defer k.Close()

	info := &OSVersion{}

	major, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err == nil {
		info.Major = major
	}

	minor, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err == nil {
		info.Minor = minor
	}

	//!: CUrrentBuildNumber is stored as a string (why??)
	build, _, err := k.GetStringValue("CurrentBuildNumber")
	if err == nil {
		info.Build = build
	}

	ubr, _, err := k.GetIntegerValue("UBR")
	if err == nil {
		info.UBR = ubr
	}

	// Before Windows 10, called "ReleaseID"
	displayVersion, _, err := k.GetStringValue("DisplayVersion")
	if err == nil {
		info.DisplayVersion = displayVersion
	} else {
		releaseId, _, errFall := k.GetStringValue("ReleaseId")
		if errFall == nil {
			info.DisplayVersion = releaseId
		}
	}

	return info, nil
}

// String to print versions in a readable way
func (v *OSVersion) String() string {
	return fmt.Sprintf("%d.%d.%s.%d (%s)", v.Major, v.Minor, v.Build, v.UBR, v.DisplayVersion)
}
