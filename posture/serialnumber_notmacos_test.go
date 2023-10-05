// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package posture

import (
	"fmt"
	"testing"

	"tailscale.com/util/cibuild"
)

func TestGetSerialNumberNotMac(t *testing.T) {
	// Do not run this test on the CI, it is mostly to help devs
	// as checking for serials on these platforms requires root
	// and they are often not set in VMs.
	if cibuild.On() {
		t.Skip()
	}

	sns, err := GetSerialNumbers()
	if err != nil {
		t.Fatalf("failed to get serial number: %s", err)
	}

	if len(sns) == 0 {
		t.Fatalf("expected at least one serial number, got %v", sns)
	}

	if len(sns[0]) <= 0 {
		t.Errorf("expected a serial number with more than zero characters, got %s", sns[0])
	}

	fmt.Printf("serials: %v\n", sns)
}
