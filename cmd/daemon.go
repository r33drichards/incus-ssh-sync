package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	interval        time.Duration
	pidFile         string
	installDaemon   bool
	uninstallDaemon bool
)

// daemonCmd represents the daemon command
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run sync as a background daemon",
	Long: `Run the sync command continuously in the background as a daemon.

This command will:
1. Run the sync command at regular intervals
2. Handle graceful shutdown on SIGINT/SIGTERM
3. Optionally install/uninstall as a system service (launchd on macOS, systemd on Linux)

Examples:
  # Run daemon with 5 minute intervals
  incus-ssh-sync daemon --interval 5m
  
  # Install as system service
  incus-ssh-sync daemon --install
  
  # Uninstall system service
  incus-ssh-sync daemon --uninstall`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if installDaemon {
			return installSystemService()
		}
		if uninstallDaemon {
			return uninstallSystemService()
		}
		return runDaemon()
	},
}

func init() {
	// Local flags for daemon command
	daemonCmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "sync interval (e.g., 30s, 5m, 1h)")
	daemonCmd.Flags().StringVar(&pidFile, "pid-file", "", "path to PID file")
	daemonCmd.Flags().BoolVar(&installDaemon, "install", false, "install as system service (launchd on macOS, systemd on Linux)")
	daemonCmd.Flags().BoolVar(&uninstallDaemon, "uninstall", false, "uninstall system service")
}

func runDaemon() error {
	if verbose {
		fmt.Printf("Starting daemon with %v interval...\n", interval)
	}

	// Set default PID file if not specified
	if pidFile == "" {
		if runtime.GOOS == "darwin" {
			pidFile = filepath.Join(os.TempDir(), "incus-ssh-sync.pid")
		} else {
			pidFile = "/tmp/incus-ssh-sync.pid"
		}
	}

	// Write PID file
	if err := writePidFile(pidFile); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	defer removePidFile(pidFile)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create ticker for sync intervals
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial sync
	if err := runSync(); err != nil {
		fmt.Printf("Initial sync failed: %v\n", err)
	}

	// Main daemon loop
	for {
		select {
		case <-ctx.Done():
			if verbose {
				fmt.Println("Daemon shutting down...")
			}
			return nil
		case sig := <-sigChan:
			if verbose {
				fmt.Printf("Received signal %v, shutting down...\n", sig)
			}
			cancel()
		case <-ticker.C:
			if verbose {
				fmt.Printf("Running sync at %v...\n", time.Now().Format(time.RFC3339))
			}
			if err := runSync(); err != nil {
				fmt.Printf("Sync failed: %v\n", err)
			}
		}
	}
}

func writePidFile(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

func removePidFile(path string) {
	os.Remove(path)
}

func installSystemService() error {
	switch runtime.GOOS {
	case "darwin":
		return installLaunchdService()
	case "linux":
		return installSystemdService()
	default:
		return fmt.Errorf("system service installation not supported on %s", runtime.GOOS)
	}
}

func uninstallSystemService() error {
	switch runtime.GOOS {
	case "darwin":
		return uninstallLaunchdService()
	case "linux":
		return uninstallSystemdService()
	default:
		return fmt.Errorf("system service uninstallation not supported on %s", runtime.GOOS)
	}
}

func installLaunchdService() error {
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get current user's home directory for config file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configFile := filepath.Join(homeDir, ".incus-ssh-sync.yaml")
	
	// Create LaunchAgent directory if it doesn't exist
	launchAgentDir := filepath.Join(homeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	// Create launchd plist content
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.incus-ssh-sync.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
		<string>--interval</string>
		<string>%v</string>
		<string>--config</string>
		<string>%s</string>
		<string>--verbose</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>`, execPath, interval, configFile, 
		filepath.Join(homeDir, "Library", "Logs", "incus-ssh-sync.log"),
		filepath.Join(homeDir, "Library", "Logs", "incus-ssh-sync.error.log"))

	plistPath := filepath.Join(launchAgentDir, "com.incus-ssh-sync.daemon.plist")

	// Create logs directory if it doesn't exist
	logsDir := filepath.Join(homeDir, "Library", "Logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Write plist file
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %w", err)
	}

	fmt.Printf("Launchd service installed at %s\n", plistPath)
	fmt.Println("To load and start the service, run:")
	fmt.Println("  launchctl load ~/Library/LaunchAgents/com.incus-ssh-sync.daemon.plist")
	fmt.Println()
	fmt.Println("To check status:")
	fmt.Println("  launchctl list | grep incus-ssh-sync")
	fmt.Println()
	fmt.Println("Logs will be written to:")
	fmt.Printf("  %s\n", filepath.Join(homeDir, "Library", "Logs", "incus-ssh-sync.log"))
	fmt.Printf("  %s\n", filepath.Join(homeDir, "Library", "Logs", "incus-ssh-sync.error.log"))

	return nil
}

func uninstallLaunchdService() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", "com.incus-ssh-sync.daemon.plist")

	// Check if plist file exists
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		fmt.Println("Launchd service is not installed")
		return nil
	}

	// Remove plist file
	if err := os.Remove(plistPath); err != nil {
		return fmt.Errorf("failed to remove plist file: %w", err)
	}

	fmt.Printf("Launchd service removed from %s\n", plistPath)
	fmt.Println("To unload the service (if running), run:")
	fmt.Println("  launchctl unload ~/Library/LaunchAgents/com.incus-ssh-sync.daemon.plist")

	return nil
}

func installSystemdService() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("installing systemd service requires root privileges")
	}

	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get current user's home directory for config file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configFile := filepath.Join(homeDir, ".incus-ssh-sync.yaml")

	// Create systemd service content
	serviceContent := fmt.Sprintf(`[Unit]
Description=Incus SSH Config Sync Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s daemon --interval %v --config %s --verbose
Restart=always
RestartSec=10
PIDFile=/var/run/incus-ssh-sync.pid

[Install]
WantedBy=multi-user.target
`, execPath, interval, configFile)

	servicePath := "/etc/systemd/system/incus-ssh-sync.service"

	// Write service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	fmt.Printf("Systemd service installed at %s\n", servicePath)
	fmt.Println("To enable and start the service, run:")
	fmt.Println("  sudo systemctl daemon-reload")
	fmt.Println("  sudo systemctl enable incus-ssh-sync")
	fmt.Println("  sudo systemctl start incus-ssh-sync")
	fmt.Println()
	fmt.Println("To check status:")
	fmt.Println("  sudo systemctl status incus-ssh-sync")

	return nil
}

func uninstallSystemdService() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("uninstalling systemd service requires root privileges")
	}

	servicePath := "/etc/systemd/system/incus-ssh-sync.service"

	// Check if service file exists
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		fmt.Println("Systemd service is not installed")
		return nil
	}

	// Remove service file
	if err := os.Remove(servicePath); err != nil {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	fmt.Printf("Systemd service removed from %s\n", servicePath)
	fmt.Println("To stop and disable the service (if running), run:")
	fmt.Println("  sudo systemctl stop incus-ssh-sync")
	fmt.Println("  sudo systemctl disable incus-ssh-sync")
	fmt.Println("  sudo systemctl daemon-reload")

	return nil
}