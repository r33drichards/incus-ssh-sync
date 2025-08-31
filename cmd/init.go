package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a default configuration file",
	Long: `Create a default configuration file for incus-ssh-sync.

This command will create a configuration file with default values at:
- $HOME/.incus-ssh-sync.yaml (default)
- Or at the path specified with --config flag

The configuration file includes settings for:
- SSH config file path
- Incus socket and remote settings
- Default user and proxy jump host
- Backup and sync options`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInit()
	},
}

func init() {
	// No local flags needed for init command
}

type Config struct {
	SSHConfig     string
	ProxyJump     string
	DefaultUser   string
	IncusSocket   string
	IncusRemote   string
	IncusRemoteURL string
	Backup        bool
	RemoveMissing bool
}

func runInit() error {
	// Determine config file path
	configPath := cfgFile
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configPath = filepath.Join(home, ".incus-ssh-sync.yaml")
	}

	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("configuration file already exists at %s", configPath)
	}

	// Create default configuration
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	config := Config{
		SSHConfig:      filepath.Join(home, ".ssh", "config"),
		ProxyJump:      "incus",
		DefaultUser:    "",
		IncusSocket:    "/var/lib/incus/unix.socket",
		IncusRemote:    "local",
		IncusRemoteURL: "",
		Backup:         true,
		RemoveMissing:  false,
	}

	// Add comments to the YAML
	configContent := `# Incus SSH Sync Configuration

# Path to your SSH config file
ssh_config: ` + config.SSHConfig + `

# ProxyJump host for SSH connections (optional)
proxy_jump: ` + config.ProxyJump + `

# Default username for SSH connections
# Leave empty to use current system username
default_user: ` + config.DefaultUser + `

# Incus socket path (for local connections)
incus_socket: ` + config.IncusSocket + `

# Incus remote name
incus_remote: ` + config.IncusRemote + `

# Incus remote URL (for remote connections via HTTPS API)
# Example: https://incus.example.com:8443
# Leave empty to use local socket connection
incus_remote_url: ` + config.IncusRemoteURL + `

# Create backup of SSH config before modifications
backup: ` + fmt.Sprintf("%t", config.Backup) + `

# Remove SSH entries for containers that no longer exist
remove_missing: ` + fmt.Sprintf("%t", config.RemoveMissing) + `
`

	// Create directory if needed
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write config file
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Configuration file created at %s\n", configPath)
	fmt.Println("\nYou can now run 'incus-ssh-sync sync' to synchronize your containers.")
	
	return nil
}