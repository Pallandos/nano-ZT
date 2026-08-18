package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// InstalledApp contains details about an application, including its SHA-256 hash and Authenticode signature status.
type InstalledApp struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher"`
	InstallLocation string `json:"install_location"`
	ExecutablePath  string `json:"executable_path"`
	SHA256          string `json:"sha256"`
	IsSigned        bool   `json:"is_signed"`
	SignatureStatus string `json:"signature_status"`
}

// --- WinVerifyTrust API Definitions ---

type wintrustFileInfo struct {
	cbStruct       uint32
	filePath       *uint16
	fileHandle     windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	fileInfo           uintptr
	stateAction        uint32
	stateData          windows.Handle
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

const (
	wtdUiNone      = 2
	wtdRevokeNone  = 0
	wtdChoiceFile  = 1
	wtdStateIgnore = 0
)

var (
	modwintrust        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = modwintrust.NewProc("WinVerifyTrust")

	// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00aac56b-c15d-11d0-8c39-00c04fc2aa2d}
	winTrustActionGenericVerifyV2 = windows.GUID{
		Data1: 0x00aac56b,
		Data2: 0xc15d,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0x39, 0x00, 0xc0, 0x4f, 0xc2, 0xaa, 0x2d},
	}
)

// GetAppVersion searches the registry for an installed application, resolves its main executable,
// computes its SHA-256 hash, and verifies its Windows Authenticode signature.
func GetAppVersion(appName string) (*InstalledApp, error) {
	registryLocations := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	targetLower := strings.ToLower(appName)

	for _, loc := range registryLocations {
		app, err := searchRegistryApp(loc.root, loc.path, targetLower)
		if err == nil && app != nil {
			_ = VerifyAndHashApp(app)
			return app, nil
		}
	}

	return nil, fmt.Errorf("application %q not found in registry", appName)
}

func searchRegistryApp(root registry.Key, basePath string, targetLower string) (*InstalledApp, error) {
	k, err := registry.OpenKey(root, basePath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

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

		if strings.Contains(strings.ToLower(displayName), targetLower) {
			version, _, _ := subK.GetStringValue("DisplayVersion")
			publisher, _, _ := subK.GetStringValue("Publisher")
			location, _, _ := subK.GetStringValue("InstallLocation")
			displayIcon, _, _ := subK.GetStringValue("DisplayIcon")

			subK.Close()

			execPath := findExecutable(location, displayIcon)

			return &InstalledApp{
				Name:            displayName,
				Version:         version,
				Publisher:       publisher,
				InstallLocation: location,
				ExecutablePath:  execPath,
			}, nil
		}

		subK.Close()
	}

	return nil, nil
}

// VerifyAndHashApp computes SHA-256 hash and verifies Authenticode digital signature for the application binary.
func VerifyAndHashApp(app *InstalledApp) error {
	if app.ExecutablePath == "" {
		app.SignatureStatus = "EXECUTABLE_NOT_FOUND"
		return fmt.Errorf("executable path not found for app %q", app.Name)
	}

	hash, errHash := ComputeSHA256(app.ExecutablePath)
	if errHash == nil {
		app.SHA256 = hash
	}

	signed, status, _ := VerifyAuthenticodeSignature(app.ExecutablePath)
	app.IsSigned = signed
	app.SignatureStatus = status

	return nil
}

// VerifyAuthenticodeSignature checks if a binary file has a valid Windows Authenticode digital signature using WinVerifyTrust.
func VerifyAuthenticodeSignature(filePath string) (bool, string, error) {
	if filePath == "" {
		return false, "NO_FILE_PATH", fmt.Errorf("file path is empty")
	}

	filePathUTF16, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return false, "INVALID_PATH", err
	}

	fi := wintrustFileInfo{
		cbStruct: uint32(unsafe.Sizeof(wintrustFileInfo{})),
		filePath: filePathUTF16,
	}

	wtData := wintrustData{
		cbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUiNone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceFile,
		fileInfo:         uintptr(unsafe.Pointer(&fi)),
		stateAction:      wtdStateIgnore,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		uintptr(windows.INVALID_HANDLE),
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&wtData)),
	)

	if ret == 0 {
		return true, "VALID_SIGNATURE", nil
	}

	return false, fmt.Sprintf("UNTRUSTED_OR_UNSIGNED (0x%x)", uint32(ret)), nil
}

// ComputeSHA256 calculates the SHA-256 checksum of a file at the given path.
func ComputeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func findExecutable(installLocation, displayIcon string) string {
	if displayIcon != "" {
		iconPath := strings.Trim(displayIcon, `"`)
		if idx := strings.Index(iconPath, ","); idx != -1 {
			iconPath = strings.TrimSpace(iconPath[:idx])
		}
		if strings.HasSuffix(strings.ToLower(iconPath), ".exe") {
			if _, err := os.Stat(iconPath); err == nil {
				return iconPath
			}
		}
	}

	if installLocation != "" {
		cleanLocation := strings.Trim(installLocation, `"`)
		if entries, err := os.ReadDir(cleanLocation); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".exe") {
					return filepath.Join(cleanLocation, entry.Name())
				}
			}
		}
	}

	return ""
}

// String returns a readable representation of the application details
func (a *InstalledApp) String() string {
	return fmt.Sprintf("%s (Version: %s, Signed: %t [%s], SHA256: %s)",
		a.Name, a.Version, a.IsSigned, a.SignatureStatus, a.SHA256)
}
