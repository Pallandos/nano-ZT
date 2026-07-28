package test

//!: This should not be considered as a "test" file as it is just testing if the function works,
//!: not its correctness

import (
	"fmt"
	"testing"

	"github.com/pallandos/nano-zt/internal/collectors"
)

func TestCollectorsAV(t *testing.T) {
	avhealth, err := collectors.GetGlobalAntivirusHealth()

	if err != nil {
		t.Errorf("Error: %s\n", err)
	} else {
		fmt.Printf("Is AV healthy : %t\n", avhealth.IsHealthy)
		fmt.Printf("Status of AV : %s\n", avhealth.Status)
		fmt.Printf("Description of AV : %s\n", avhealth.Description)
	}
}
