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
//	cd cmd/tailcat-dagger && go run . all
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"dagger.io/dagger"
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
		tarTag    = fs.String("tar-tag", "golang:1.26.4-alpine", "image tag to import from the tarball")
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

	opts := []dagger.ClientOpt{dagger.WithLogOutput(os.Stderr)}
	if *verbose {
		opts = append(opts, dagger.WithLogOutput(os.Stderr))
	}
	client, err := dagger.Connect(ctx, opts...)
	if err != nil {
		log.Fatalf("dagger connect: %v", err)
	}
	defer client.Close()

	root, err := findRepoRoot(*repoRoot)
	if err != nil {
		log.Fatalf("repo root: %v", err)
	}

	src := client.Host().Directory(root, dagger.HostDirectoryOpts{
		Exclude: []string{
			".git",
			".omo",
			"kimi-export-session_*.md",
			"dist",
			"*.wasm",
		},
	})

	var base *dagger.Container
	if *imageTar != "" {
		tarFile := client.Host().File(*imageTar)
		base = client.Container().Import(tarFile, dagger.ContainerImportOpts{Tag: *tarTag})
	} else {
		base = client.Container().From(*baseImage)
	}
	modCache := client.Host().Directory(filepath.Join(os.Getenv("HOME"), "go", "pkg", "mod"))
	base = base.
		WithMountedDirectory("/go/pkg/mod", modCache).
		WithMountedCache("/root/.cache/go-build", client.CacheVolume("go-build")).
		WithEnvVariable("GOCACHE", "/root/.cache/go-build").
		WithEnvVariable("GOFLAGS", "-mod=readonly").
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithEnvVariable("GOPROXY", "off").
		WithEnvVariable("GOSUMDB", "off").
		WithDirectory("/src", src).
		WithWorkdir("/src")

	switch cmd {
	case "version":
		if err := run(ctx, base, "go", "version"); err != nil {
			log.Fatalf("version: %v", err)
		}
	case "build":
		if err := run(ctx, base, "go", "build", "./..."); err != nil {
			log.Fatalf("build: %v", err)
		}
		fmt.Println("build: ok")
	case "test":
		if err := run(ctx, base, "go", "test", "-count=1", "-timeout", "120s", "./..."); err != nil {
			log.Fatalf("test: %v", err)
		}
		fmt.Println("test: ok")
	case "vet":
		if err := run(ctx, base, "go", "vet", "./..."); err != nil {
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
	case "all":
		if err := run(ctx, base, "go", "build", "./..."); err != nil {
			log.Fatalf("build: %v", err)
		}
		if err := run(ctx, base, "go", "vet", "./..."); err != nil {
			log.Fatalf("vet: %v", err)
		}
		if err := run(ctx, base, "go", "test", "-count=1", "-timeout", "120s", "./..."); err != nil {
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

func run(ctx context.Context, ctr *dagger.Container, args ...string) error {
	cmdLine := strings.Join(args, " ")
	// The wrapper always exits 0 so Dagger lets us read the captured
	// stdout, stderr, and exit-code files even when the real command fails.
	script := fmt.Sprintf("%s > /tmp/run.stdout 2> /tmp/run.stderr; echo $? > /tmp/run.exitcode; exit 0", cmdLine)
	runner := ctr.WithExec([]string{"sh", "-c", script})
	_, _ = runner.Sync(ctx)
	out, _ := runner.File("/tmp/run.stdout").Contents(ctx)
	errOut, _ := runner.File("/tmp/run.stderr").Contents(ctx)
	exitCodeBytes, _ := runner.File("/tmp/run.exitcode").Contents(ctx)
	if out != "" {
		fmt.Fprintln(os.Stdout, out)
	}
	if errOut != "" {
		fmt.Fprintln(os.Stderr, errOut)
	}
	exitCode := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(exitCodeBytes), "%d", &exitCode); err != nil {
		return fmt.Errorf("failed to parse exit code: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("exit code: %d", exitCode)
	}
	return nil
}

func buildWasm(ctx context.Context, base *dagger.Container, root string) error {
	wasm := base.
		WithEnvVariable("GOOS", "js").
		WithEnvVariable("GOARCH", "wasm").
		WithExec([]string{"go", "build", "-o", "/tmp/tailcat-web.wasm", "./web"}).
		File("/tmp/tailcat-web.wasm")
	_, err := wasm.Export(ctx, filepath.Join(root, "tailcat-web.wasm"))
	return err
}

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
