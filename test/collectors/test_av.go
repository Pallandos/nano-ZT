package test

import (
	"fmt"

	"github.com/pallandos/nano-zt/internal/collectors"
)

func main() {
	avhealth, err := collectors.GetGlobalAntivirusHealth()

	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Printf("Is AV healthy : %t", avhealth.IsHealthy)
		fmt.Printf("Status of AV : %s", avhealth.Status)
		fmt.Printf("Description of AV : %s", avhealth.Description)
	}
}
