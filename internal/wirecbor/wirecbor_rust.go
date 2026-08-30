// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build rust

package wirecbor

/*
#cgo LDFLAGS: -L${SRCDIR}/target/release -lwirecbor -Wl,-rpath,${SRCDIR}/target/release
#include <stdlib.h>
#include <stdint.h>

// wirecbor_encode_json encodes a JSON description of WireConnInfo into CBOR.
// The returned buffer must be freed with wirecbor_buffer_free.
int wirecbor_encode_json(const char *json_in, uint8_t **out_bytes, size_t *out_len);

// wirecbor_decode_json decodes a CBOR buffer into a JSON description of WireConnInfo.
// The returned string must be freed with wirecbor_string_free.
int wirecbor_decode_json(const uint8_t *cbor_in, size_t cbor_len, char **out_json);

// wirecbor_buffer_free frees a buffer returned by wirecbor_encode_json.
void wirecbor_buffer_free(uint8_t *ptr, size_t len);

// wirecbor_string_free frees a string returned by wirecbor_decode_json.
void wirecbor_string_free(char *ptr);
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unsafe"
)

func available() bool { return true }

func encode(ci *WireConnInfo) ([]byte, error) {
	j, err := json.Marshal(bridgeToJSONConnInfo(ci))
	if err != nil {
		return nil, fmt.Errorf("wirecbor encode json: %w", err)
	}
	cstr := C.CString(string(j))
	defer C.free(unsafe.Pointer(cstr))

	var outBytes *C.uint8_t
	var outLen C.size_t
	ret := C.wirecbor_encode_json(cstr, &outBytes, &outLen)
	if ret != 0 {
		return nil, fmt.Errorf("wirecbor encode failed: %d", ret)
	}
	if outBytes == nil || outLen == 0 {
		return nil, fmt.Errorf("wirecbor encode returned empty buffer")
	}
	// SAFETY: wirecbor_encode_json promises outBytes points to outLen valid
	// bytes allocated by Rust; we copy them immediately and then free.
	b := C.GoBytes(unsafe.Pointer(outBytes), C.int(outLen))
	C.wirecbor_buffer_free(outBytes, outLen)
	return b, nil
}

func decode(cborIn []byte) (*WireConnInfo, error) {
	if len(cborIn) == 0 {
		return nil, fmt.Errorf("wirecbor decode: empty input")
	}
	var outJSON *C.char
	ret := C.wirecbor_decode_json((*C.uint8_t)(unsafe.Pointer(&cborIn[0])), C.size_t(len(cborIn)), &outJSON)
	if ret != 0 {
		return nil, fmt.Errorf("wirecbor decode failed: %d", ret)
	}
	if outJSON == nil {
		return nil, fmt.Errorf("wirecbor decode returned nil string")
	}
	// SAFETY: wirecbor_decode_json promises outJSON is a NUL-terminated C
	// string allocated by Rust; we copy it with C.GoString and then free.
	j := C.GoString(outJSON)
	C.wirecbor_string_free(outJSON)

	var jc jsonConnInfo
	if err := json.Unmarshal([]byte(j), &jc); err != nil {
		return nil, fmt.Errorf("wirecbor decode json: %w", err)
	}
	return jsonToBridgeConnInfo(&jc), nil
}

// jsonConnInfo is the Rust/Go JSON bridge for WireConnInfo. ServerPublic is
// hex-encoded so both sides can (de)serialize it without a third crate on the
// Rust side and without custom JSON marshalers on the Go side.
type jsonConnInfo struct {
	ServerPublicHex string        `json:"ServerPublic"`
	Region          []*jsonRegion `json:"Region,omitempty"`
	RegionID        int           `json:"RegionID,omitempty"`
}

type jsonRegion struct {
	RegionID   int         `json:"RegionID,omitempty"`
	RegionCode string      `json:"RegionCode,omitempty"`
	RegionName string      `json:"RegionName,omitempty"`
	Nodes      []*jsonNode `json:"Nodes,omitempty"`
}

type jsonNode struct {
	Name             string `json:"Name,omitempty"`
	RegionID         int    `json:"RegionID,omitempty"`
	HostName         string `json:"HostName,omitempty"`
	CertName         string `json:"CertName,omitempty"`
	IPv4             string `json:"IPv4,omitempty"`
	IPv6             string `json:"IPv6,omitempty"`
	STUNPort         int    `json:"STUNPort,omitempty"`
	DERPPort         int    `json:"DERPPort,omitempty"`
	InsecureForTests bool   `json:"InsecureForTests,omitempty"`
}

func bridgeToJSONConnInfo(ci *WireConnInfo) *jsonConnInfo {
	jc := &jsonConnInfo{
		ServerPublicHex: hex.EncodeToString(ci.ServerPublic[:]),
		RegionID:        ci.RegionID,
	}
	for _, r := range ci.Region {
		jr := &jsonRegion{
			RegionID:   r.RegionID,
			RegionCode: r.RegionCode,
			RegionName: r.RegionName,
		}
		for _, n := range r.Nodes {
			jr.Nodes = append(jr.Nodes, &jsonNode{
				Name:             n.Name,
				RegionID:         n.RegionID,
				HostName:         n.HostName,
				CertName:         n.CertName,
				IPv4:             n.IPv4,
				IPv6:             n.IPv6,
				STUNPort:         n.STUNPort,
				DERPPort:         n.DERPPort,
				InsecureForTests: n.InsecureForTests,
			})
		}
		jc.Region = append(jc.Region, jr)
	}
	return jc
}

func jsonToBridgeConnInfo(jc *jsonConnInfo) *WireConnInfo {
	ci := &WireConnInfo{
		RegionID: jc.RegionID,
	}
	if b, err := hex.DecodeString(jc.ServerPublicHex); err == nil && len(b) == 32 {
		copy(ci.ServerPublic[:], b)
	}
	for _, jr := range jc.Region {
		r := &WireRegion{
			RegionID:   jr.RegionID,
			RegionCode: jr.RegionCode,
			RegionName: jr.RegionName,
		}
		for _, jn := range jr.Nodes {
			r.Nodes = append(r.Nodes, &WireNode{
				Name:             jn.Name,
				RegionID:         jn.RegionID,
				HostName:         jn.HostName,
				CertName:         jn.CertName,
				IPv4:             jn.IPv4,
				IPv6:             jn.IPv6,
				STUNPort:         jn.STUNPort,
				DERPPort:         jn.DERPPort,
				InsecureForTests: jn.InsecureForTests,
			})
		}
		ci.Region = append(ci.Region, r)
	}
	return ci
}
