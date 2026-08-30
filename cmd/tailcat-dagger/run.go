// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"dagger.io/dagger"
)

// run executes args inside ctr using a shell wrapper that always exits 0 so
// Dagger lets us read the captured stdout, stderr, and exit-code files even
// when the real command fails.
func run(ctx context.Context, ctr *dagger.Container, args ...string) error {
	cmdLine := strings.Join(args, " ")
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

// runVersion prints the Go toolchain version inside the container.
func runVersion(ctx context.Context, base *dagger.Container) error {
	return run(ctx, base, "go", "version")
}

// runBuild compiles the entire module.
func runBuild(ctx context.Context, base *dagger.Container) error {
	return run(ctx, base, "go", "build", "./...")
}

// runVet runs go vet on the module.
func runVet(ctx context.Context, base *dagger.Container) error {
	return run(ctx, base, "go", "vet", "./...")
}

// runTest runs the module tests.
func runTest(ctx context.Context, base *dagger.Container) error {
	return run(ctx, base, "go", "test", "-count=1", "-timeout", "120s", "./...")
}
