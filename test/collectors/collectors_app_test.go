package test

//!: This should not be considered as a "test" file as it is just testing if the function works,
//!: not its correctness

import (
	"fmt"
	"testing"

	"github.com/pallandos/nano-zt/internal/collectors"
)

func TestCollectorsAppVersionSecurity(t *testing.T) {
	appName := "Windows"
	app, err := collectors.GetAppVersion(appName)

	if err != nil {
		fmt.Printf("App search for %q result: %s\n", appName, err)
	} else {
		fmt.Printf("App details:\n")
		fmt.Printf("  Name:             %s\n", app.Name)
		fmt.Printf("  Version:          %s\n", app.Version)
		fmt.Printf("  Publisher:        %s\n", app.Publisher)
		fmt.Printf("  Executable Path:  %s\n", app.ExecutablePath)
		fmt.Printf("  SHA-256:          %s\n", app.SHA256)
		fmt.Printf("  Is Signed:        %t\n", app.IsSigned)
		fmt.Printf("  Signature Status: %s\n", app.SignatureStatus)
	}
}
