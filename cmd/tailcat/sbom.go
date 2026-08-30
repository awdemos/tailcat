// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
)

func runSBOM() {
	args := flag.Args()
	outDir := "sbom"
	scanTarget := "."
	if len(args) > 1 {
		// tailcat sbom [target] [outdir]
		scanTarget = args[1]
		if len(args) > 2 {
			outDir = args[2]
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("sbom: create output dir: %v", err)
	}

	syft, err := exec.LookPath("syft")
	if err != nil {
		log.Fatalf("sbom: syft not found in PATH: %v", err)
	}

	cdxPath := filepath.Join(outDir, "sbom.cdx.json")
	spdxPath := filepath.Join(outDir, "sbom.spdx.json")
	cmd := exec.Command(syft, "scan", scanTarget,
		"-o", "cyclonedx-json="+cdxPath,
		"-o", "spdx-json="+spdxPath,
		"-q",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("sbom: syft scan: %v", err)
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatalf("sbom: no build info available (binary not built with modules)")
	}
	type modInfo struct {
		Path    string `json:"path"`
		Version string `json:"version"`
		Sum     string `json:"sum"`
		Replace string `json:"replace,omitempty"`
	}
	mods := []modInfo{}
	for _, d := range info.Deps {
		m := modInfo{Path: d.Path, Version: d.Version, Sum: d.Sum}
		if r := d.Replace; r != nil {
			m.Replace = r.Path
			if r.Version != "" {
				m.Replace += " " + r.Version
			}
		}
		mods = append(mods, m)
	}
	out := struct {
		Main      string    `json:"main"`
		GoVersion string    `json:"goVersion"`
		Modules   []modInfo `json:"modules"`
	}{
		Main:      info.Main.Path,
		GoVersion: info.GoVersion,
		Modules:   mods,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatalf("sbom: marshal buildinfo: %v", err)
	}
	buildinfoPath := filepath.Join(outDir, "buildinfo.json")
	if err := os.WriteFile(buildinfoPath, b, 0o644); err != nil {
		log.Fatalf("sbom: write buildinfo: %v", err)
	}
	fmt.Printf("wrote %s, %s, %s\n", cdxPath, spdxPath, buildinfoPath)
}
