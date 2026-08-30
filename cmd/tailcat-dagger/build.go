// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"dagger.io/dagger"
)

// buildWasm compiles the web wasm artifact and exports it to root.
func buildWasm(ctx context.Context, base *dagger.Container, root string) error {
	wasm := base.
		WithEnvVariable("GOOS", "js").
		WithEnvVariable("GOARCH", "wasm").
		WithEnvVariable("GOCACHE", "/root/.cache/go-wasm-build").
		WithExec([]string{"go", "build", "-o", "/tmp/tailcat-web.wasm", "./web"}).
		File("/tmp/tailcat-web.wasm")
	_, err := wasm.Export(ctx, filepath.Join(root, "tailcat-web.wasm"))
	return err
}

// buildWebdemo builds the static web demo distribution and exports it to
// root/dist, keeping only the gzipped wasm.
func buildWebdemo(ctx context.Context, base *dagger.Container, root string) error {
	dist := base.
		WithExec([]string{"go", "run", "./cmd/tailcat-webdist", "-o", "/dist"}).
		Directory("/dist")

	// Keep only the gzipped wasm, matching the old GitHub Pages workflow.
	dist = dist.
		WithoutFile("main.wasm").
		WithoutFile("main.wasm.zst")

	out := filepath.Join(root, "dist")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	_, err := dist.Export(ctx, out)
	return err
}

func buildSBOMs(ctx context.Context, client *dagger.Client, base *dagger.Container, root string) error {
	outDir := filepath.Join(root, "sbom")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	syftBin := client.Host().File(filepath.Join(os.Getenv("HOME"), ".local", "bin", "syft"))
	sbomContainer := base.
		WithMountedFile("/usr/local/bin/syft", syftBin, dagger.ContainerWithMountedFileOpts{Owner: "0:0"}).
		WithExec([]string{"syft", "scan", "/src", "-o", "cyclonedx-json=/tmp/sbom.cdx.json", "-o", "spdx-json=/tmp/sbom.spdx.json", "-q"})

	cdxFile := sbomContainer.File("/tmp/sbom.cdx.json")
	if _, err := cdxFile.Export(ctx, filepath.Join(outDir, "sbom.cdx.json")); err != nil {
		return fmt.Errorf("syft cyclonedx export: %w", err)
	}
	spdxFile := sbomContainer.File("/tmp/sbom.spdx.json")
	if _, err := spdxFile.Export(ctx, filepath.Join(outDir, "sbom.spdx.json")); err != nil {
		return fmt.Errorf("syft spdx export: %w", err)
	}
	return nil
}
