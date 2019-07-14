// +build mage

package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	Default    = Build
	goFiles    = getGoFiles()
	goSrcFiles = getGoSrcFiles()
)

var curDir = func() string {
	name, _ := os.Getwd()
	return name
}()

// Calculate file paths
var toolsBinDir = normalizePath(path.Join(curDir, "tools", "bin"))

func init() {
	time.Local = time.UTC

	// Add local bin in PATH
	err := os.Setenv("PATH", fmt.Sprintf("%s:%s", toolsBinDir, os.Getenv("PATH")))
	if err != nil {
		panic(err)
	}
}

func Build() {
	banner := figure.NewFigure("CVE Db", "", true)
	banner.Print()

	fmt.Println("")
	color.Red("# Build Info ---------------------------------------------------------------")
	fmt.Printf("Go version : %s\n", runtime.Version())
	fmt.Printf("Git revision : %s\n", hash())
	fmt.Printf("Git branch : %s\n", branch())
	fmt.Printf("Tag : %s\n", tag())

	fmt.Println("")

	color.Red("# Core packages ------------------------------------------------------------")
	mg.SerialDeps(Go.Deps, Go.License, Go.Generate, Go.Format, Go.Import, Go.Lint, Go.Test)

	fmt.Println("")
	color.Red("# Artifacts ----------------------------------------------------------------")
	mg.Deps(Bin.CVEDb)
}

// -----------------------------------------------------------------------------

type Ci mg.Namespace

// Validate circleci configuration file (circleci/config.yml).
func (Ci) Validate() error {
	return sh.RunV("circleci-cli", "config", "validate")
}

// execute circleci job build on local.
func (ci Ci) Build() error {
	return ci.localExecute("build")
}

func (ci Ci) localExecute(job string) error {
	return sh.RunV("circleci-cli", "local", "execute", "--job", job)
}

// -----------------------------------------------------------------------------

type Gen mg.Namespace

// Generate initializers
func (Gen) Wire() {
	color.Blue("### Wiring dispatchers")
	mustGoGenerate("HTTP", "go.zenithar.org/cvedb/cli/cvedb/internal/dispatchers/http")
}

// Generate protobuf
func (Gen) Protobuf() error {
	color.Blue("### Protobuf")

	return sh.RunV("prototool", "all", "--fix", "pkg/protocol")
}

// -----------------------------------------------------------------------------

type Go mg.Namespace

// Generate go code
func (Go) Generate() error {
	color.Cyan("## Generate code")
	mg.SerialDeps(Gen.Protobuf, Gen.Wire)
	return nil
}

// Test run go test
func (Go) Test() error {
	color.Cyan("## Running unit tests")
	sh.Run("mkdir", "-p", "test-results/junit")
	return sh.RunV("gotestsum", "--junitfile", "test-results/junit/unit-tests.xml", "--", "-short", "-race", "-cover", "./...")
}

// Test run go test
func (Go) IntegrationTest() {
	color.Cyan("## Running integration tests")
	sh.Run("mkdir", "-p", "test-results/junit")

	// runIntegrationTest("Repositories", "go.zenithar.org/spotigraph/internal/repositories/test/integration")
}

// Tidy add/remove depenedencies.
func (Go) Tidy() error {
	fmt.Println("## Cleaning go modules")
	return sh.RunV("go", "mod", "tidy", "-v")
}

// Deps install dependency tools.
func (Go) Deps() error {
	color.Cyan("## Vendoring dependencies")
	return sh.RunV("go", "mod", "vendor")
}

// Deps install dependency tools.
func (Go) License() error {
	color.Cyan("## Check license")
	return sh.RunV("wwhrd", "check")
}

// Format runs gofmt on everything
func (Go) Format() error {
	color.Cyan("## Format everything")
	args := []string{"-s", "-w"}
	args = append(args, goFiles...)
	return sh.RunV("gofumpt", args...)
}

// Import runs goimports on everything
func (Go) Import() error {
	color.Cyan("## Process imports")
	args := []string{"-w"}
	args = append(args, goSrcFiles...)
	return sh.RunV("goreturns", args...)
}

// Lint run linter.
func (Go) Lint() error {
	mg.Deps(Go.Format)
	color.Cyan("## Lint go code")
	return sh.RunV("golangci-lint", "run")
}

// -----------------------------------------------------------------------------

type Docker mg.Namespace

// Build docker image.
func (Docker) Build() error {
	color.Red("# Docker -------------------------------------------------------------------")
	fmt.Printf("BUILD_DATE : %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("VERSION : %s\n", tag())
	fmt.Printf("VCS_REF : %s\n", hash())

	fmt.Printf(" > Production image\n")
	return sh.RunV("docker", "build",
		"-f", "deployment/docker/Dockerfile",
		"--build-arg", fmt.Sprintf("BUILD_DATE=%s", time.Now().Format(time.RFC3339)),
		"--build-arg", fmt.Sprintf("VERSION=%s", tag()),
		"--build-arg", fmt.Sprintf("VCS_REF=%s", hash()),
		"-t", "cvedb:latest",
		".")
}

// -----------------------------------------------------------------------------

type Bin mg.Namespace

func (Bin) CVEDb() error {
	return goBuild("go.zenithar.org/cvedb/cli/cvedb", "cvedb")
}

func goBuild(packageName, out string) error {
	fmt.Printf(" > Building %s [%s]\n", out, packageName)

	varsSetByLinker := map[string]string{
		"go.zenithar.org/cvedb/internal/version.Version":   tag(),
		"go.zenithar.org/cvedb/internal/version.Revision":  hash(),
		"go.zenithar.org/cvedb/internal/version.Branch":    branch(),
		"go.zenithar.org/cvedb/internal/version.BuildUser": os.Getenv("USER"),
		"go.zenithar.org/cvedb/internal/version.BuildDate": time.Now().Format(time.RFC3339),
		"go.zenithar.org/cvedb/internal/version.GoVersion": runtime.Version(),
	}
	var linkerArgs []string
	for name, value := range varsSetByLinker {
		linkerArgs = append(linkerArgs, "-X", fmt.Sprintf("%s=%s", name, value))
	}
	linkerArgs = append(linkerArgs, "-s", "-w")

	return sh.RunWith(map[string]string{
		"CGO_ENABLED": "0",
	}, "go", "build", "-ldflags", strings.Join(linkerArgs, " "), "-o", fmt.Sprintf("bin/%s", out), packageName)
}

// -----------------------------------------------------------------------------

func getGoFiles() []string {
	var goFiles []string

	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, "vendor/") {
			return filepath.SkipDir
		}
		if strings.Contains(path, "tools/") {
			return filepath.SkipDir
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		goFiles = append(goFiles, path)
		return nil
	})

	return goFiles
}

func getGoSrcFiles() []string {
	var goSrcFiles []string

	for _, path := range goFiles {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}

		goSrcFiles = append(goSrcFiles, path)
	}

	return goSrcFiles
}

// tag returns the git tag for the current branch or "" if none.
func tag() string {
	s, _ := sh.Output("git", "describe", "--tags")
	return s
}

// hash returns the git hash for the current repo or "" if none.
func hash() string {
	hash, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return hash
}

// branch returns the git branch for current repo
func branch() string {
	hash, _ := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	return hash
}

func mustStr(r string, err error) string {
	if err != nil {
		panic(err)
	}
	return r
}

func mustGoGenerate(txt, name string) {
	fmt.Printf(" > %s [%s]\n", txt, name)
	err := sh.RunV("go", "generate", name)
	if err != nil {
		panic(err)
	}
}

func runIntegrationTest(txt, name string) {
	fmt.Printf(" > %s [%s]\n", txt, name)
	err := sh.RunV("gotestsum", "--junitfile", fmt.Sprintf("test-results/junit/integration-%s.xml", strings.ToLower(txt)), name, "--", "-tags=integration", "-race")
	if err != nil {
		panic(err)
	}
}

// normalizePath turns a path into an absolute path and removes symlinks
func normalizePath(name string) string {
	absPath := mustStr(filepath.Abs(name))
	return absPath
}
