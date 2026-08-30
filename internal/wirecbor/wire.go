// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wirecbor implements an optional Rust-backed fast path for CBOR
// encoding and decoding of connection blobs (ConnBlob wire format). When the
// "rust" build tag is not set, the package falls back to the pure-Go
// fxamacker/cbor implementation.
package wirecbor

// WireConnInfo is the wire form of a tailcat connection blob. It mirrors
// the root package's wireConnInfo so that the Rust fast path and the pure-Go
// fallback produce identical CBOR bytes.
type WireConnInfo struct {
	ServerPublic [32]byte       `cbor:"p" json:"ServerPublic"`
	Region       []*WireRegion  `cbor:"r,omitempty" json:"Region,omitempty"`
	RegionID     int            `cbor:"i,omitempty" json:"RegionID,omitempty"`
}

// WireRegion is the wire form of a DERP region embedded in a ConnBlob.
type WireRegion struct {
	RegionID   int         `cbor:"i,omitempty" json:"RegionID,omitempty"`
	RegionCode string      `cbor:"c,omitempty" json:"RegionCode,omitempty"`
	RegionName string      `cbor:"m,omitempty" json:"RegionName,omitempty"`
	Nodes      []*WireNode `cbor:"N,omitempty" json:"Nodes,omitempty"`
}

// WireNode is the wire form of a DERP node embedded in a ConnBlob.
type WireNode struct {
	Name     string `cbor:"n,omitempty" json:"Name,omitempty"`
	RegionID int    `cbor:"i,omitempty" json:"RegionID,omitempty"`
	HostName string `cbor:"h,omitempty" json:"HostName,omitempty"`
	CertName string `cbor:"t,omitempty" json:"CertName,omitempty"`
	IPv4     string `cbor:"4,omitempty" json:"IPv4,omitempty"`
	IPv6     string `cbor:"6,omitempty" json:"IPv6,omitempty"`
	STUNPort int    `cbor:"s,omitempty" json:"STUNPort,omitempty"`
	DERPPort int    `cbor:"d,omitempty" json:"DERPPort,omitempty"`
	InsecureForTests bool `cbor:"x,omitempty" json:"InsecureForTests,omitempty"`
}
