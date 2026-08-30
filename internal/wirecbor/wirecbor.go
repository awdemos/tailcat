// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:generate sh build.sh

package wirecbor

// Available reports whether the Rust fast path is linked and available.
// It is true only when the package is compiled with the "rust" build tag
// and the static library has been built.
func Available() bool {
	return available()
}

// Encode serializes ci as CBOR using the Rust fast path if available,
// otherwise the pure-Go fallback.
func Encode(ci *WireConnInfo) ([]byte, error) {
	return encode(ci)
}

// Decode parses a CBOR-encoded WireConnInfo using the Rust fast path if
// available, otherwise the pure-Go fallback.
func Decode(cborIn []byte) (*WireConnInfo, error) {
	return decode(cborIn)
}
