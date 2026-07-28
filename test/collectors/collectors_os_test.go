package test

import (
	"fmt"
	"testing"

	"github.com/pallandos/nano-zt/internal/collectors"
)

func TestCollectorsOSvers(t *testing.T) {
	osVersion, err := collectors.GetOSVersion()

	if err != nil {
		t.Errorf("Error: %s\n", err)
	} else {
		fmt.Printf("OS version print: %s\n", osVersion)

		fmt.Printf("Major: %d\n", osVersion.Major)
		fmt.Printf("Minor: %d\n", osVersion.Minor)
		fmt.Printf("Build: %s\n", osVersion.Build)
		fmt.Printf("Security patch: %d\n", osVersion.UBR)
		fmt.Printf("Display Version: %s\n", osVersion.DisplayVersion)
	}
}
