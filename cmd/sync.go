package cmd

import (
	"fmt"
	"os"

	"incus-ssh-sync/pkg/incus"
	"incus-ssh-sync/pkg/ssh"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	dryRun         bool
	nameFilter     string
	statusFilter   string
	forceOverwrite bool
)

// syncCmd represents the sync command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync Incus containers to SSH config",
	Long: `Synchronize Incus container information to your SSH config file.

This command will:
1. Connect to the Incus server
2. Get information about all containers
3. Update the SSH config file with entries for each container

Example:
  incus-ssh-sync sync --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSync()
	},
}

func init() {
	// Local flags for sync command
	syncCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be done without making changes")
	syncCmd.Flags().StringVar(&nameFilter, "name-filter", "", "only include containers whose names match this pattern")
	syncCmd.Flags().StringVar(&statusFilter, "status", "", "only include containers with this status (e.g., 'Running')")
	syncCmd.Flags().BoolVar(&forceOverwrite, "force", false, "overwrite existing entries even if manually modified")

	// Bind flags to viper
	viper.BindPFlag("remove_missing", syncCmd.Flags().Lookup("remove-missing"))
	viper.BindPFlag("backup", syncCmd.Flags().Lookup("backup"))
	viper.BindPFlag("ssh_config", syncCmd.Flags().Lookup("ssh-config"))
	viper.BindPFlag("proxy_jump", syncCmd.Flags().Lookup("proxy-jump"))
	viper.BindPFlag("default_user", syncCmd.Flags().Lookup("default-user"))
}

func runSync() error {
	if verbose {
		fmt.Println("Starting Incus SSH config sync...")
	}

	// Get configuration values
	sshConfigPath := viper.GetString("ssh_config")
	proxyJump := viper.GetString("proxy_jump")
	defaultUser := viper.GetString("default_user")
	incusSocket := viper.GetString("incus_socket")
	incusRemote := viper.GetString("incus_remote")
	incusRemoteURL := viper.GetString("incus_remote_url")
	authToken := viper.GetString("auth_token")
	removeMissing := viper.GetBool("remove_missing")

	// Connect to Incus
	client, err := incus.NewClientWithAuth(incusSocket, incusRemote, incusRemoteURL, authToken)
	if err != nil {
		return fmt.Errorf("failed to connect to Incus server: %w", err)
	}

	// Get container information
	containers, err := client.ListContainers(nameFilter, statusFilter)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if verbose {
		fmt.Printf("Found %d containers\n", len(containers))
	}

	// Build a fresh SSH config to overwrite the target file
	config := &ssh.Config{
		Hosts: make(map[string]*ssh.HostEntry),
		Lines: []string{},
	}

	// Track changes
	var added, updated, removed int

	// Process containers
	existingHosts := make(map[string]bool)
	for _, container := range containers {
		// Skip containers without IP
		if container.IPAddress == "" {
			if verbose {
				fmt.Printf("Skipping container %s: no IP address\n", container.Name)
			}
			continue
		}

		// Determine username
		username := defaultUser
		if username == "" {
			username = os.Getenv("USER")
		}

		// Check if entry exists
		existingHosts[container.Name] = true
		hostExists := ssh.HostExists(config, container.Name)

		// Create or update entry
		entry := ssh.HostEntry{
			Name:      container.Name,
			HostName:  container.IPAddress,
			ProxyJump: proxyJump,
			User:      username,
		}

		if !hostExists {
			if dryRun {
				fmt.Printf("[DRY RUN] Would add entry for %s (IP: %s)\n", container.Name, container.IPAddress)
			} else {
				if err := ssh.AddHost(config, entry); err != nil {
					return fmt.Errorf("failed to add host %s: %w", container.Name, err)
				}
				if verbose {
					fmt.Printf("Added entry for %s (IP: %s)\n", container.Name, container.IPAddress)
				}
			}
			added++
		} else {
			currentIP := ssh.GetHostIP(config, container.Name)
			if currentIP != container.IPAddress || forceOverwrite {
				if dryRun {
					fmt.Printf("[DRY RUN] Would update entry for %s (IP: %s -> %s)\n", container.Name, currentIP, container.IPAddress)
				} else {
					if err := ssh.UpdateHost(config, entry); err != nil {
						return fmt.Errorf("failed to update host %s: %w", container.Name, err)
					}
					if verbose {
						fmt.Printf("Updated entry for %s (IP: %s -> %s)\n", container.Name, currentIP, container.IPAddress)
					}
				}
				updated++
			} else if verbose {
				fmt.Printf("Entry for %s already up to date (IP: %s)\n", container.Name, container.IPAddress)
			}
		}
	}

	// Remove entries for non-existent containers if requested
	if removeMissing {
		hosts := ssh.GetAllHosts(config)
		for _, host := range hosts {
			if !existingHosts[host] {
				if dryRun {
					fmt.Printf("[DRY RUN] Would remove entry for %s (container no longer exists)\n", host)
				} else {
					if err := ssh.RemoveHost(config, host); err != nil {
						return fmt.Errorf("failed to remove host %s: %w", host, err)
					}
					if verbose {
						fmt.Printf("Removed entry for %s (container no longer exists)\n", host)
					}
				}
				removed++
			}
		}
	}

	// Write updated config if not in dry run mode
	if !dryRun {
		if err := ssh.WriteConfig(config, sshConfigPath); err != nil {
			return fmt.Errorf("failed to write SSH config: %w", err)
		}
		fmt.Printf("SSH config updated successfully at %s\n", sshConfigPath)
	}

	// Summary
	fmt.Printf("Summary: %d added, %d updated", added, updated)
	if removeMissing {
		fmt.Printf(", %d removed", removed)
	}
	if dryRun {
		fmt.Printf(" (dry run)")
	}
	fmt.Println()

	return nil
}
