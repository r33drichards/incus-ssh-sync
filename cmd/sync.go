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

	servers, err := getServerConfigs()
	if err != nil {
		return err
	}

	var totalAdded, totalUpdated, totalRemoved int

	for _, server := range servers {
		if verbose {
			fmt.Printf("\n[server=%s] syncing to %s\n", server.ProxyJump, server.SSHConfig)
		}

		client, err := incus.NewClientWithAuth(server.IncusSocket, server.IncusRemote, server.IncusRemoteURL, server.AuthToken)
		if err != nil {
			return fmt.Errorf("[%s] failed to connect to Incus server: %w", server.ProxyJump, err)
		}

		containers, err := client.ListContainers(nameFilter, statusFilter)
		if err != nil {
			return fmt.Errorf("[%s] failed to list containers: %w", server.ProxyJump, err)
		}

		if verbose {
			fmt.Printf("[%s] found %d containers\n", server.ProxyJump, len(containers))
		}

		config := &ssh.Config{
			Hosts:                  make(map[string]*ssh.HostEntry),
			Lines:                  []string{},
			DisableHostKeyChecking: server.SkipHostKeyCheck,
		}

		var added, updated, removed int
		existingHosts := make(map[string]bool)
		for _, container := range containers {
			if container.IPAddress == "" {
				if verbose {
					fmt.Printf("[%s] skipping %s: no IP address\n", server.ProxyJump, container.Name)
				}
				continue
			}

			username := server.DefaultUser
			if username == "" {
				username = os.Getenv("USER")
			}

			existingHosts[container.Name] = true
			hostExists := ssh.HostExists(config, container.Name)

			entry := ssh.HostEntry{
				Name:      container.Name,
				HostName:  container.IPAddress,
				ProxyJump: server.ProxyJump,
				User:      username,
			}

			if !hostExists {
				if dryRun {
					fmt.Printf("[%s][DRY RUN] Would add %s (IP: %s)\n", server.ProxyJump, container.Name, container.IPAddress)
				} else {
					if err := ssh.AddHost(config, entry); err != nil {
						return fmt.Errorf("[%s] failed to add host %s: %w", server.ProxyJump, container.Name, err)
					}
					if verbose {
						fmt.Printf("[%s] added %s (IP: %s)\n", server.ProxyJump, container.Name, container.IPAddress)
					}
				}
				added++
			} else {
				currentIP := ssh.GetHostIP(config, container.Name)
				if currentIP != container.IPAddress || forceOverwrite {
					if dryRun {
						fmt.Printf("[%s][DRY RUN] Would update %s (IP: %s -> %s)\n", server.ProxyJump, container.Name, currentIP, container.IPAddress)
					} else {
						if err := ssh.UpdateHost(config, entry); err != nil {
							return fmt.Errorf("[%s] failed to update host %s: %w", server.ProxyJump, container.Name, err)
						}
						if verbose {
							fmt.Printf("[%s] updated %s (IP: %s -> %s)\n", server.ProxyJump, container.Name, currentIP, container.IPAddress)
						}
					}
					updated++
				} else if verbose {
					fmt.Printf("[%s] %s already up to date (IP: %s)\n", server.ProxyJump, container.Name, container.IPAddress)
				}
			}
		}

		if server.RemoveMissing {
			hosts := ssh.GetAllHosts(config)
			for _, host := range hosts {
				if !existingHosts[host] {
					if dryRun {
						fmt.Printf("[%s][DRY RUN] Would remove %s (container no longer exists)\n", server.ProxyJump, host)
					} else {
						if err := ssh.RemoveHost(config, host); err != nil {
							return fmt.Errorf("[%s] failed to remove host %s: %w", server.ProxyJump, host, err)
						}
						if verbose {
							fmt.Printf("[%s] removed %s (container no longer exists)\n", server.ProxyJump, host)
						}
					}
					removed++
				}
			}
		}

		if !dryRun {
			if err := ssh.WriteConfig(config, server.SSHConfig); err != nil {
				return fmt.Errorf("[%s] failed to write SSH config: %w", server.ProxyJump, err)
			}
			fmt.Printf("[%s] SSH config updated at %s\n", server.ProxyJump, server.SSHConfig)
		}

		if verbose || dryRun {
			fmt.Printf("[%s] Summary: %d added, %d updated", server.ProxyJump, added, updated)
			if server.RemoveMissing {
				fmt.Printf(", %d removed", removed)
			}
			if dryRun {
				fmt.Printf(" (dry run)")
			}
			fmt.Println()
		}

		totalAdded += added
		totalUpdated += updated
		totalRemoved += removed
	}

	fmt.Printf("Total: %d added, %d updated", totalAdded, totalUpdated)
	if totalRemoved > 0 {
		fmt.Printf(", %d removed", totalRemoved)
	}
	if dryRun {
		fmt.Printf(" (dry run)")
	}
	fmt.Println()

	return nil
}
