// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wirecbor

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestRoundTripMinimal(t *testing.T) {
	ci := &WireConnInfo{
		ServerPublic: random32(),
		RegionID:     302,
	}
	b, err := Encode(ci)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ServerPublic != ci.ServerPublic || got.RegionID != ci.RegionID {
		t.Fatalf("mismatch: got %+v, want %+v", got, ci)
	}
}

func TestRoundTripFull(t *testing.T) {
	ci := &WireConnInfo{
		ServerPublic: random32(),
		Region: []*WireRegion{{
			RegionID:   10,
			RegionCode: "sea",
			RegionName: "Seattle",
			Nodes: []*WireNode{{
				Name:             "10b",
				RegionID:         10,
				HostName:         "derp10b.example.com",
				CertName:         "cert.example.com",
				IPv4:             "192.0.2.1",
				IPv6:             "2001:db8::1",
				STUNPort:         3478,
				DERPPort:         8443,
				InsecureForTests: true,
			}},
		}},
	}
	b, err := Encode(ci)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Region[0].Nodes[0].HostName != "derp10b.example.com" {
		t.Fatalf("host name mismatch: %q", got.Region[0].Nodes[0].HostName)
	}
	if !got.Region[0].Nodes[0].InsecureForTests {
		t.Fatalf("InsecureForTests lost")
	}
}

func TestDecodeBadInput(t *testing.T) {
	if _, err := Decode([]byte{0xff}); err == nil {
		t.Fatal("expected error for invalid CBOR")
	}
}

func TestAvailableMatchesBuildTag(t *testing.T) {
	if Available() {
		t.Log("Rust fast path is linked")
	} else {
		t.Log("using pure-Go fallback")
	}
}

func TestEncodeMatchesGoCBOR(t *testing.T) {
	if Available() {
		t.Skip("skipping equivalence check against self when Rust path is active")
	}
	ci := sampleConnInfo()
	b, err := Encode(ci)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The pure-Go fallback uses cbor.Marshal on the same struct tags, so it
	// should be byte-for-byte identical to a direct cbor.Marshal of an
	// equivalent struct.
	want, err := goCBORMarshal(ci)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("encode mismatch:\n got %x\nwant %x", b, want)
	}
}

func random32() [32]byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b
}

func goCBORMarshal(ci *WireConnInfo) ([]byte, error) {
	return cbor.Marshal(ci)
}

func sampleConnInfo() *WireConnInfo {
	return &WireConnInfo{
		ServerPublic: random32(),
		Region: []*WireRegion{{
			RegionID:   20,
			RegionCode: "nyc",
			RegionName: "New York",
			Nodes: []*WireNode{{
				Name:     "20a",
				RegionID: 20,
				HostName: "derp20a.example.com",
				IPv4:     "198.51.100.1",
				STUNPort: 3478,
				DERPPort: 443,
			}},
		}},
		RegionID: 20,
	}
}
