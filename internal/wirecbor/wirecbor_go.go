// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !rust

package wirecbor

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

func available() bool { return false }

func encode(ci *WireConnInfo) ([]byte, error) {
	b, err := cbor.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("wirecbor encode: %w", err)
	}
	return b, nil
}

func decode(cborIn []byte) (*WireConnInfo, error) {
	ci := new(WireConnInfo)
	if err := cbor.Unmarshal(cborIn, ci); err != nil {
		return nil, fmt.Errorf("wirecbor decode: %w", err)
	}
	return ci, nil
}
