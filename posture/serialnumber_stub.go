// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || !darwin

package posture

import "errors"

// GetSerialNumber returns a list of any serial numbers
// found on the client
func GetSerialNumbers() ([]string, error) {
	return []string{}, errors.New("not implemented")
}
