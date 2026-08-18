package test

//!: This should not be considered as a "test" file as it is just testing if the function works,
//!: not its correctness

import (
	"fmt"
	"testing"

	"github.com/pallandos/nano-zt/internal/collectors"
)

func TestCollectorsAppVersion(t *testing.T) {
	// Loose match demo
	appName := "Windows"
	app, err := collectors.GetAppVersion(appName)

	if err != nil {
		fmt.Printf("Loose app search for %q result: %s\n", appName, err)
	} else {
		fmt.Printf("App found (loose): %s\n", app)
	}
}

func TestCollectorsAppVersionStrict(t *testing.T) {
	// Strict match demo checking both exact name and expected publisher
	appName := "Google Chrome"
	publisher := "Google LLC"

	app, err := collectors.GetAppVersionStrict(appName, publisher)

	if err != nil {
		fmt.Printf("Strict app search for %q by %q result: %s\n", appName, publisher, err)
	} else {
		fmt.Printf("App found (strict): %s\n", app)
		fmt.Printf("Name: %s\n", app.Name)
		fmt.Printf("Version: %s\n", app.Version)
		fmt.Printf("Publisher: %s\n", app.Publisher)
		fmt.Printf("Install Location: %s\n", app.InstallLocation)
	}
}

func TestCollectorsListApps(t *testing.T) {
	apps, err := collectors.ListInstalledApps()

	if err != nil {
		t.Errorf("Error: %s\n", err)
	} else {
		fmt.Printf("Total installed applications found: %d\n", len(apps))
		limit := 5
		if len(apps) < limit {
			limit = len(apps)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("App [%d]: %s (Version: %s)\n", i+1, apps[i].Name, apps[i].Version)
		}
	}
}
