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

// buildBaseContainer returns a prepared container for the tailcat module.
// It mounts the module cache read-only and a writable go-build cache, sets
// offline module resolution, and adds the source directory at /src.
func buildBaseContainer(
	client *dagger.Client,
	root, baseImage, imageTar, tarTag string,
) *dagger.Container {
	src := client.Host().Directory(root, dagger.HostDirectoryOpts{
		Exclude: []string{
			".git",
			".omo",
			"kimi-export-session_*.md",
			"dist",
			"*.wasm",
			"sbom",
		},
	})

	var ctr *dagger.Container
	if imageTar != "" {
		tarFile := client.Host().File(imageTar)
		ctr = client.Container().Import(tarFile, dagger.ContainerImportOpts{Tag: tarTag})
	} else {
		ctr = client.Container().From(baseImage)
	}

	modCache := client.Host().Directory(filepath.Join(os.Getenv("HOME"), "go", "pkg", "mod"))
	return ctr.
		WithMountedDirectory("/go/pkg/mod", modCache, dagger.ContainerWithMountedDirectoryOpts{ReadOnly: true}).
		WithMountedCache("/root/.cache/go-build", client.CacheVolume("go-build")).
		WithMountedCache("/root/.cache/go-wasm-build", client.CacheVolume("go-wasm-build")).
		WithEnvVariable("GOCACHE", "/root/.cache/go-build").
		WithEnvVariable("GOWASMBuildCache", "/root/.cache/go-wasm-build").
		WithEnvVariable("GOFLAGS", "-mod=readonly").
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithEnvVariable("GOPROXY", "off").
		WithEnvVariable("GOSUMDB", "off").
		WithDirectory("/src", src).
		WithWorkdir("/src")
}

// findRepoRoot returns explicit if set, otherwise walks up from the current
// working directory looking for a .git directory.
func findRepoRoot(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root containing .git")
		}
		dir = parent
	}
}

// newDaggerClient connects to the Dagger engine with stderr logging.
func newDaggerClient(ctx context.Context, verbose bool) (*dagger.Client, error) {
	opts := []dagger.ClientOpt{dagger.WithLogOutput(os.Stderr)}
	if verbose {
		opts = append(opts, dagger.WithLogOutput(os.Stderr))
	}
	return dagger.Connect(ctx, opts...)
}
