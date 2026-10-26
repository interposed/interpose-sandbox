package doctor

import "testing"

// The core requirement: a microVM request on a host with no /dev/kvm must fall
// back to the process (sandlock) tier, never fail or try to boot a microVM.
func TestSelectTierMicroVMFallsBackToSandlockWithoutKVM(t *testing.T) {
	cap := Capability{KVM: false, ProcessAvailable: true, ProcessBackend: "landlock"}
	tier, fellBack, err := SelectTier(TierMicroVM, cap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tier != TierProcess {
		t.Fatalf("tier = %q, want %q (sandlock fallback)", tier, TierProcess)
	}
	if !fellBack {
		t.Fatal("fellBack = false, want true (microVM asked, KVM absent)")
	}
}

func TestSelectTierAutoPicksProcessWithoutKVM(t *testing.T) {
	cap := Capability{KVM: false, ProcessAvailable: true}
	tier, fellBack, err := SelectTier(TierAuto, cap)
	if err != nil || tier != TierProcess {
		t.Fatalf("auto => (%q, %v, %v), want process", tier, fellBack, err)
	}
	if fellBack {
		t.Fatal("auto selection should not report a fallback")
	}
}

func TestSelectTierProcessRequestNeedsProcessBackend(t *testing.T) {
	// No backend at all (e.g. CGO-off build on an unsupported host).
	none := Capability{KVM: false, ProcessAvailable: false}
	if _, _, err := SelectTier(TierProcess, none); err == nil {
		t.Fatal("process request with no backend should error")
	}
	if _, _, err := SelectTier(TierAuto, none); err == nil {
		t.Fatal("auto with no backend should error")
	}
	if _, _, err := SelectTier(TierMicroVM, none); err == nil {
		t.Fatal("microVM request with no backend (and no KVM) should error")
	}
}

func TestBestTierReportsProcessOnKVMHostUntilBackendBuilt(t *testing.T) {
	// microVMBuilt is false today: even a KVM host runs the process tier, but it
	// is still reported as microVM-capable (its ceiling), which the control
	// plane uses to label the workspace.
	cap := Capability{KVM: true, ProcessAvailable: true}
	if got := cap.BestTier(); got != TierProcess {
		t.Fatalf("BestTier on KVM host = %q, want %q while microVM backend is unbuilt", got, TierProcess)
	}
	if !cap.MicroVMCapable() {
		t.Fatal("MicroVMCapable() = false on a KVM host, want true")
	}
}

func TestSelectTierUnknownErrors(t *testing.T) {
	if _, _, err := SelectTier(Tier("bogus"), Capability{ProcessAvailable: true}); err == nil {
		t.Fatal("unknown tier should error")
	}
}
