#!/bin/sh
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# Build the Rust static library for the wirecbor fast path.
# Run from the repo root or from internal/wirecbor.
set -e
cd "$(dirname "$0")"
cargo build --release
