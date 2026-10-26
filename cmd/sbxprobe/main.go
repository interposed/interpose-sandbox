// Command sbxprobe reports this host's sandbox capability and how each tier
// request resolves. It is a diagnostic: run it on a candidate host to see
// whether it can do microVMs or falls back to the process (sandlock) tier.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/interposed/interpose-sandbox/pkg/doctor"
)

func main() {
	cap := doctor.Probe()
	b, _ := json.MarshalIndent(cap, "", "  ")
	fmt.Println("capability:")
	fmt.Println(string(b))
	fmt.Printf("microVM-capable: %v   best-tier: %s\n\n", cap.MicroVMCapable(), cap.BestTier())

	for _, want := range []doctor.Tier{doctor.TierAuto, doctor.TierMicroVM, doctor.TierProcess} {
		t, fellBack, err := doctor.SelectTier(want, cap)
		label := string(want)
		if label == "" {
			label = "auto"
		}
		fmt.Printf("request %-8s -> tier=%-8s fellBack=%-5v err=%v\n", label, t, fellBack, err)
	}
}
