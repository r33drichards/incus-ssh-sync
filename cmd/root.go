package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	debug   bool
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

	// Add commands
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(connectCmd)
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
