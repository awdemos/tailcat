// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command tailcat-dagger runs CI/build pipelines for the tailcat project
// using the Dagger Go SDK. It is the replacement for the removed GitHub
// Actions workflows.
//
// Usage:
//
//	cd cmd/tailcat-dagger && go run . build
//	cd cmd/tailcat-dagger && go run . build -tar /path/to/golang-image.tar
//	cd cmd/tailcat-dagger && go run . test
//	cd cmd/tailcat-dagger && go run . vet
//	cd cmd/tailcat-dagger && go run . wasm
//	cd cmd/tailcat-dagger && go run . webdemo
//	cd cmd/tailcat-dagger && go run . sbom
//	cd cmd/tailcat-dagger && go run . all
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/sync/errgroup"
)

const goImage = "10.88.0.8:5000/golang:1.26.5-alpine"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var (
		baseImage = fs.String("image", goImage, "base container image")
		imageTar  = fs.String("tar", "", "path to a local image tarball to import instead of pulling from a registry")
		tarTag    = fs.String("tar-tag", goImage, "image tag to import from the tarball")
		repoRoot  = fs.String("root", "", "project repo root (auto-detected if empty)")
		timeout   = fs.Duration("timeout", 0, "per-step timeout (0 = none)")
		verbose   = fs.Bool("v", false, "verbose Dagger output")
	)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	client, err := newDaggerClient(ctx, *verbose)
	if err != nil {
		log.Fatalf("dagger connect: %v", err)
	}
	defer client.Close()

	root, err := findRepoRoot(*repoRoot)
	if err != nil {
		log.Fatalf("repo root: %v", err)
	}

	base := buildBaseContainer(client, root, *baseImage, *imageTar, *tarTag)

	switch cmd {
	case "version":
		if err := runVersion(ctx, base); err != nil {
			log.Fatalf("version: %v", err)
		}
	case "build":
		if err := runBuild(ctx, base); err != nil {
			log.Fatalf("build: %v", err)
		}
		fmt.Println("build: ok")
	case "test":
		if err := runTest(ctx, base); err != nil {
			log.Fatalf("test: %v", err)
		}
		fmt.Println("test: ok")
	case "vet":
		if err := runVet(ctx, base); err != nil {
			log.Fatalf("vet: %v", err)
		}
		fmt.Println("vet: ok")
	case "wasm":
		if err := buildWasm(ctx, base, root); err != nil {
			log.Fatalf("wasm: %v", err)
		}
		fmt.Println("wasm: ok")
	case "webdemo":
		if err := buildWebdemo(ctx, base, root); err != nil {
			log.Fatalf("webdemo: %v", err)
		}
		fmt.Println("webdemo: ok")
	case "sbom":
		if err := buildSBOMs(ctx, client, base, root); err != nil {
			log.Fatalf("sbom: %v", err)
		}
		fmt.Println("sbom: ok")
	case "all":
		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error { return runBuild(ctx, base) })
		g.Go(func() error { return runVet(ctx, base) })
		g.Go(func() error { return runTest(ctx, base) })
		if err := g.Wait(); err != nil {
			log.Fatalf("all: %v", err)
		}
		fmt.Println("all: ok")
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <build|test|vet|wasm|webdemo|sbom|all> [flags]\n", os.Args[0])
}
