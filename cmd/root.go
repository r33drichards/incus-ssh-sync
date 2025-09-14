package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"incus-ssh-sync/pkg/incus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile          string
	verbose          bool
	debug            bool
	ipAddressFlag    string
	snapshotNameFlag string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "incus-ssh-sync",
	Short: "Sync Incus container information to SSH config",
	Long: `A CLI tool that automatically syncs Incus container information to your SSH config file.

It connects to the Incus server, retrieves container names and IP addresses,
and updates your SSH config file with appropriate Host entries using the format:

Host container-name
  HostName container-ip
  ProxyJump incus
  User your-username`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// If both restore flags are provided, perform snapshot restore.
		if ipAddressFlag != "" && snapshotNameFlag != "" {
			servers, err := getServerConfigs()
			if err != nil {
				return err
			}

			for _, server := range servers {
				client, err := incus.NewClientWithAuth(server.IncusSocket, server.IncusRemote, server.IncusRemoteURL, server.AuthToken)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "[warn][%s] failed to connect: %v\n", server.ProxyJump, err)
					}
					continue
				}

				container, err := client.FindContainerByIP(ipAddressFlag)
				if err != nil {
					return fmt.Errorf("[%s] failed to search containers: %w", server.ProxyJump, err)
				}
				if container == nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "[%s] no container with IP %s\n", server.ProxyJump, ipAddressFlag)
					}
					continue
				}

				if verbose {
					fmt.Printf("[%s] restoring %s to snapshot %s (IP: %s)\n", server.ProxyJump, container.Name, snapshotNameFlag, ipAddressFlag)
				}
				if err := client.RestoreSnapshot(container.Name, snapshotNameFlag); err != nil {
					return fmt.Errorf("[%s] restore failed for container %s to snapshot %q (IP %s): %w", server.ProxyJump, container.Name, snapshotNameFlag, ipAddressFlag, err)
				}
				fmt.Printf("Restored %s to snapshot %s\n", container.Name, snapshotNameFlag)
				return nil
			}

			return fmt.Errorf("no container found with IP %s across configured servers", ipAddressFlag)
		}

		// Otherwise show help
		return cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.incus-ssh-sync.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug output")

	// Root-level restore-by-IP flags
	rootCmd.Flags().StringVar(&ipAddressFlag, "ip-address", "", "IPv4 address of the container to restore")
	rootCmd.Flags().StringVar(&snapshotNameFlag, "snapshot-name", "", "Name of the snapshot to restore")

	// Add commands
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(installCmd)
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error finding home directory:", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".incus-ssh-sync" (without extension)
		viper.AddConfigPath(home)
		viper.SetConfigName(".incus-ssh-sync")
	}

	// Read environment variables prefixed with INCUS_SSH_SYNC_
	viper.SetEnvPrefix("INCUS_SSH_SYNC")
	viper.AutomaticEnv()

	// Set default values
	setDefaultConfig()

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

// setDefaultConfig sets default values for configuration
func setDefaultConfig() {
	home, err := os.UserHomeDir()
	if err == nil {
		viper.SetDefault("ssh_config", filepath.Join(home, ".ssh", "config"))
	}
	viper.SetDefault("proxy_jump", "incus")
	viper.SetDefault("default_user", "")
	viper.SetDefault("incus_socket", "/var/lib/incus/unix.socket")
	viper.SetDefault("incus_remote", "local")
	viper.SetDefault("incus_remote_url", "")
	viper.SetDefault("auth_token", "")
	viper.SetDefault("backup", true)
	viper.SetDefault("remove_missing", false)
	viper.SetDefault("skip_host_key_check", true)
}

// ServerConfig represents one Incus/SSH sync target.
type ServerConfig struct {
	SSHConfig        string `mapstructure:"ssh_config"`
	ProxyJump        string `mapstructure:"proxy_jump"`
	DefaultUser      string `mapstructure:"default_user"`
	IncusSocket      string `mapstructure:"incus_socket"`
	IncusRemote      string `mapstructure:"incus_remote"`
	IncusRemoteURL   string `mapstructure:"incus_remote_url"`
	AuthToken        string `mapstructure:"auth_token"`
	Backup           bool   `mapstructure:"backup"`
	RemoveMissing    bool   `mapstructure:"remove_missing"`
	SkipHostKeyCheck bool   `mapstructure:"skip_host_key_check"`
}

// getServerConfigs returns all configured servers. If `servers` is not set,
// it falls back to a single server built from top-level keys for backward compatibility.
func getServerConfigs() ([]ServerConfig, error) {
	var servers []ServerConfig

	if viper.IsSet("servers") {
		if err := viper.UnmarshalKey("servers", &servers); err != nil {
			return nil, fmt.Errorf("failed to parse servers configuration: %w", err)
		}
	}

	// Backward-compatible single-server configuration
	if len(servers) == 0 {
		servers = []ServerConfig{{
			SSHConfig:        viper.GetString("ssh_config"),
			ProxyJump:        viper.GetString("proxy_jump"),
			DefaultUser:      viper.GetString("default_user"),
			IncusSocket:      viper.GetString("incus_socket"),
			IncusRemote:      viper.GetString("incus_remote"),
			IncusRemoteURL:   viper.GetString("incus_remote_url"),
			AuthToken:        viper.GetString("auth_token"),
			Backup:           viper.GetBool("backup"),
			RemoveMissing:    viper.GetBool("remove_missing"),
			SkipHostKeyCheck: viper.GetBool("skip_host_key_check"),
		}}
	} else {
		// Ensure defaults are applied for any missing fields on each server
		for i := range servers {
			if servers[i].SSHConfig == "" {
				if home, err := os.UserHomeDir(); err == nil {
					servers[i].SSHConfig = filepath.Join(home, ".ssh", "config")
				}
			}
			if servers[i].ProxyJump == "" {
				servers[i].ProxyJump = viper.GetString("proxy_jump")
			}
			if servers[i].IncusSocket == "" {
				servers[i].IncusSocket = viper.GetString("incus_socket")
			}
			if servers[i].IncusRemote == "" {
				servers[i].IncusRemote = viper.GetString("incus_remote")
			}
			// backup default is true; only override when explicitly set at top-level
			if !viper.IsSet("servers.") && viper.IsSet("backup") && !servers[i].Backup {
				servers[i].Backup = viper.GetBool("backup")
			}
			if !viper.IsSet("servers.") && viper.IsSet("remove_missing") && !servers[i].RemoveMissing {
				servers[i].RemoveMissing = viper.GetBool("remove_missing")
			}
			if !viper.IsSet("servers.") && viper.IsSet("skip_host_key_check") && !servers[i].SkipHostKeyCheck {
				servers[i].SkipHostKeyCheck = viper.GetBool("skip_host_key_check")
			}
		}
	}

	return servers, nil
}

// findServersByProxyJumps filters by proxy_jump names. If names is empty, all servers are returned.
func findServersByProxyJumps(names []string) ([]ServerConfig, error) {
	servers, err := getServerConfigs()
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return servers, nil
	}
	nameSet := map[string]struct{}{}
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	filtered := make([]ServerConfig, 0, len(names))
	for _, s := range servers {
		if _, ok := nameSet[s.ProxyJump]; ok {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no servers matched by proxy_jump: %v", names)
	}
	return filtered, nil
}
