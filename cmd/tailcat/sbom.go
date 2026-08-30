// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"time"

	"golang.org/x/sync/errgroup"
)

func runSBOM(args []string) {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	cacheDir := fs.String("cache", ".cache/tailcat-sbom", "directory for cached SBOM artifacts")
	force := fs.Bool("force", false, "regenerate SBOMs even if cached artifacts exist")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: tailcat sbom [-cache=DIR] [-force] [target] [outdir]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		log.Fatalf("sbom: %v", err)
	}
	args = fs.Args()

	outDir := "sbom"
	scanTarget := "."
	if len(args) > 0 {
		scanTarget = args[0]
		if len(args) > 1 {
			outDir = args[1]
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("sbom: create output dir: %v", err)
	}

	key, err := sbomCacheKey(scanTarget)
	if err != nil {
		log.Fatalf("sbom: compute cache key: %v", err)
	}

	syft, err := exec.LookPath("syft")
	if err != nil {
		log.Fatalf("sbom: syft not found in PATH: %v", err)
	}

	cdxPath := filepath.Join(outDir, "sbom.cdx.json")
	spdxPath := filepath.Join(outDir, "sbom.spdx.json")
	buildinfoPath := filepath.Join(outDir, "buildinfo.json")

	var cachedCDX, cachedSPDX string
	useCache := !*force
	if useCache {
		cachedCDX, cachedSPDX, useCache = findCachedSBOMs(*cacheDir, key)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if useCache {
			if err := copyFile(cdxPath, cachedCDX); err != nil {
				return fmt.Errorf("copy cached CycloneDX: %w", err)
			}
			if err := copyFile(spdxPath, cachedSPDX); err != nil {
				return fmt.Errorf("copy cached SPDX: %w", err)
			}
			fmt.Println("sbom: using cached syft output")
			return nil
		}
		if err := os.MkdirAll(*cacheDir, 0o755); err != nil {
			return fmt.Errorf("create cache dir: %w", err)
		}
		cacheCDX := filepath.Join(*cacheDir, key+"-sbom.cdx.json")
		cacheSPDX := filepath.Join(*cacheDir, key+"-sbom.spdx.json")
		cmd := exec.Command(syft, "scan", scanTarget,
			"-o", "cyclonedx-json="+cacheCDX,
			"-o", "spdx-json="+cacheSPDX,
			"-q",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("syft scan: %w", err)
		}
		if err := copyFile(cdxPath, cacheCDX); err != nil {
			return fmt.Errorf("copy CycloneDX to output: %w", err)
		}
		if err := copyFile(spdxPath, cacheSPDX); err != nil {
			return fmt.Errorf("copy SPDX to output: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		b, err := buildinfoJSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(buildinfoPath, b, 0o644); err != nil {
			return fmt.Errorf("write buildinfo: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		log.Fatalf("sbom: %v", err)
	}
	fmt.Printf("wrote %s, %s, %s\n", cdxPath, spdxPath, buildinfoPath)
}

func sbomCacheKey(target string) (string, error) {
	h := sha256.New()
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	h.Write([]byte(abs))

	// Hash go.mod and go.sum if present: these dominate SBOM output.
	for _, name := range []string{"go.mod", "go.sum"} {
		p := filepath.Join(abs, name)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(h, "\n%s %d %d", name, st.Size(), st.ModTime().UnixNano())
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		io.Copy(h, f)
		f.Close()
	}

	// Hash the tree shape: relative paths, sizes, and mod times.
	var entries []string
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entries = append(entries, fmt.Sprintf("%s\t%d\t%d", rel, info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(entries)
	for _, e := range entries {
		h.Write([]byte(e))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func findCachedSBOMs(cacheDir, key string) (cdx, spdx string, ok bool) {
	cdx = filepath.Join(cacheDir, key+"-sbom.cdx.json")
	spdx = filepath.Join(cacheDir, key+"-sbom.spdx.json")
	if _, err := os.Stat(cdx); err != nil {
		return "", "", false
	}
	if _, err := os.Stat(spdx); err != nil {
		return "", "", false
	}
	return cdx, spdx, true
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func buildinfoJSON() ([]byte, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf("no build info available (binary not built with modules)")
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
		Time      string    `json:"time"`
		Modules   []modInfo `json:"modules"`
	}{
		Main:      info.Main.Path,
		GoVersion: info.GoVersion,
		Time:      time.Now().UTC().Format(time.RFC3339),
		Modules:   mods,
	}
	return json.MarshalIndent(out, "", "  ")
}
