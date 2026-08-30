// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command tailcat-dagger runs CI/build pipelines for the tailcat project
// using the Dagger Go SDK. It is the replacement for the removed GitHub
// Actions workflows.
//
// Usage:
//
//	cd cmd/tailcat-dagger && go run . build
//	cd cmd/tailcat-dagger && go run . test
//	cd cmd/tailcat-dagger && go run . vet
//	cd cmd/tailcat-dagger && go run . wasm
//	cd cmd/tailcat-dagger && go run . webdemo
//	cd cmd/tailcat-dagger && go run . all
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"dagger.io/dagger"
)

const goImage = "golang:1.27"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var (
		baseImage = fs.String("image", goImage, "base container image")
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

	opts := []dagger.ClientOpt{dagger.WithLogOutput(os.Stderr)}
	if *verbose {
		opts = append(opts, dagger.WithLogOutput(os.Stderr))
	}
	client, err := dagger.Connect(ctx, opts...)
	if err != nil {
		log.Fatalf("dagger connect: %v", err)
	}
	defer client.Close()

	src := client.Host().Directory(".", dagger.HostDirectoryOpts{
		Exclude: []string{
			".git",
			".omo",
			"kimi-export-session_*.md",
			"dist",
			"*.wasm",
		},
	})

	base := client.Container().
		From(*baseImage).
		WithMountedCache("/go/pkg/mod", client.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", client.CacheVolume("go-build")).
		WithEnvVariable("GOCACHE", "/root/.cache/go-build").
		WithEnvVariable("GOFLAGS", "-mod=readonly").
		WithDirectory("/src", src).
		WithWorkdir("/src").
		WithExec([]string{"go", "mod", "download"})

	switch cmd {
	case "build":
		if err := run(ctx, base.WithExec([]string{"go", "build", "./..."})); err != nil {
			log.Fatalf("build: %v", err)
		}
		fmt.Println("build: ok")
	case "test":
		if err := run(ctx, base.WithExec([]string{"go", "test", "-count=1", "-timeout", "120s", "./..."})); err != nil {
			log.Fatalf("test: %v", err)
		}
		fmt.Println("test: ok")
	case "vet":
		if err := run(ctx, base.WithExec([]string{"go", "vet", "./..."})); err != nil {
			log.Fatalf("vet: %v", err)
		}
		fmt.Println("vet: ok")
	case "wasm":
		if err := buildWasm(ctx, base); err != nil {
			log.Fatalf("wasm: %v", err)
		}
		fmt.Println("wasm: ok")
	case "webdemo":
		if err := buildWebdemo(ctx, base); err != nil {
			log.Fatalf("webdemo: %v", err)
		}
		fmt.Println("webdemo: ok")
	case "all":
		if err := run(ctx, base.WithExec([]string{"go", "build", "./..."})); err != nil {
			log.Fatalf("build: %v", err)
		}
		if err := run(ctx, base.WithExec([]string{"go", "vet", "./..."})); err != nil {
			log.Fatalf("vet: %v", err)
		}
		if err := run(ctx, base.WithExec([]string{"go", "test", "-count=1", "-timeout", "120s", "./..."})); err != nil {
			log.Fatalf("test: %v", err)
		}
		fmt.Println("all: ok")
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <build|test|vet|wasm|webdemo|all> [flags]\n", os.Args[0])
}

func run(ctx context.Context, ctr *dagger.Container) error {
	_, err := ctr.Sync(ctx)
	return err
}

func buildWasm(ctx context.Context, base *dagger.Container) error {
	wasm := base.
		WithEnvVariable("GOOS", "js").
		WithEnvVariable("GOARCH", "wasm").
		WithExec([]string{"go", "build", "-o", "/tmp/tailcat-web.wasm", "./web"}).
		File("/tmp/tailcat-web.wasm")
	_, err := wasm.Export(ctx, "tailcat-web.wasm")
	return err
}

func buildWebdemo(ctx context.Context, base *dagger.Container) error {
	dist := base.
		WithExec([]string{"go", "run", "./cmd/tailcat-webdist", "-o", "/dist"}).
		Directory("/dist")

	// Keep only the gzipped wasm, matching the old GitHub Pages workflow.
	dist = dist.
		WithoutFile("main.wasm").
		WithoutFile("main.wasm.zst")

	out := filepath.Join("dist")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	_, err := dist.Export(ctx, out)
	return err
}
