package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var (
	installPath  string
	installForce bool
)

// installCmd installs the current binary into a system path
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install incus-ssh-sync into your system path",
	Long: `Copy the currently running incus-ssh-sync binary into a system directory
for convenient use. By default installs to /usr/local/bin/incus-ssh-sync.

Examples:
  incus-ssh-sync install
  incus-ssh-sync install --path /usr/local/bin
  incus-ssh-sync install --path /usr/local/bin/incus-ssh-sync --force`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInstall()
	},
}

func init() {
	installCmd.Flags().StringVar(&installPath, "path", "/usr/local/bin", "destination directory or full file path for installation (default /usr/local/bin)")
	installCmd.Flags().BoolVar(&installForce, "force", false, "overwrite existing binary if present")
}

func runInstall() error {
	// Resolve source executable path
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(srcPath); err == nil {
		srcPath = resolved
	}

	// Determine destination path
	destPath := installPath
	info, err := os.Stat(destPath)
	if err == nil && info.IsDir() {
		destPath = filepath.Join(destPath, "incus-ssh-sync")
	} else if errors.Is(err, os.ErrNotExist) {
		// If the parent exists and path ends with a separator ambiguity, treat as file path
		parent := filepath.Dir(destPath)
		if parent == "." {
			// If user provided a bare name, install into /usr/local/bin with the provided name
			destPath = filepath.Join("/usr/local/bin", destPath)
		}
	}

	// If source and destination are the same, nothing to do
	if sameFile(srcPath, destPath) {
		fmt.Printf("Binary already installed at %s\n", destPath)
		return nil
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Handle existing destination
	if _, err := os.Stat(destPath); err == nil {
		if !installForce {
			return fmt.Errorf("destination already exists: %s (use --force to overwrite)", destPath)
		}
	}

	// Copy to a temporary file first, then atomically replace
	tmpDest := destPath + ".tmp-" + fmt.Sprintf("%d", os.Getpid())
	if err := copyFile(srcPath, tmpDest, 0755); err != nil {
		return err
	}
	defer os.Remove(tmpDest)

	if err := os.Rename(tmpDest, destPath); err != nil {
		return fmt.Errorf("failed to place binary at destination (need sudo?): %w", err)
	}

	fmt.Printf("Installed incus-ssh-sync to %s\n", destPath)

	// PATH hint if needed
	dir := filepath.Dir(destPath)
	if !dirInPath(dir) {
		shell := filepath.Base(os.Getenv("SHELL"))
		fmt.Printf("Note: %s is not in your PATH.\n", dir)
		switch shell {
		case "zsh":
			fmt.Printf("Add it with: echo 'export PATH=\"%s:$PATH\"' >> ~/.zshrc && source ~/.zshrc\n", dir)
		case "bash":
			fmt.Printf("Add it with: echo 'export PATH=\"%s:$PATH\"' >> ~/.bashrc && source ~/.bashrc\n", dir)
		default:
			fmt.Printf("Add %s to your shell's PATH to use incus-ssh-sync globally.\n", dir)
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcF, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer srcF.Close()

	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("failed to create destination file (need sudo?): %w", err)
	}
	defer dstF.Close()

	if _, err := io.Copy(dstF, srcF); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := dstF.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	return nil
}

func sameFile(a, b string) bool {
	// Attempt to resolve and compare absolute paths
	aAbs, aErr := filepath.Abs(a)
	bAbs, bErr := filepath.Abs(b)
	if aErr == nil && bErr == nil && aAbs == bAbs {
		return true
	}

	aInfo, aStatErr := os.Stat(a)
	bInfo, bStatErr := os.Stat(b)
	if aStatErr != nil || bStatErr != nil {
		return false
	}
	return os.SameFile(aInfo, bInfo)
}

func detectDefaultInstallDir() string {
	pathEnv := os.Getenv("PATH")
	pathDirs := filepath.SplitList(pathEnv)

	if runtime.GOOS == "darwin" {
		if dirExists("/opt/homebrew/bin") && dirInPath("/opt/homebrew/bin") {
			return "/opt/homebrew/bin"
		}
		if dirExists("/usr/local/bin") && dirInPath("/usr/local/bin") {
			return "/usr/local/bin"
		}
	}

	if dirExists("/usr/local/bin") && dirInPath("/usr/local/bin") {
		return "/usr/local/bin"
	}

	if home, _ := os.UserHomeDir(); home != "" {
		hb := filepath.Join(home, "bin")
		if dirInPath(hb) || dirExists(hb) {
			return hb
		}
	}

	for _, d := range pathDirs {
		if d == "" {
			continue
		}
		if isSystemBin(d) {
			continue
		}
		if dirExists(d) {
			return d
		}
	}

	return "/usr/local/bin"
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func dirInPath(dir string) bool {
	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		if filepath.Clean(p) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

func isSystemBin(dir string) bool {
	sys := []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin"}
	dir = filepath.Clean(dir)
	for _, s := range sys {
		if filepath.Clean(s) == dir || strings.HasPrefix(dir, filepath.Clean(s)+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
