package cmd

import (
	"fmt"
	"os"

	"incus-ssh-sync/pkg/incus"

	"github.com/spf13/cobra"
)

var (
	ipAddressFlag    string
	snapshotNameFlag string
)

// restoreCmd restores a container to a snapshot by looking up the container by IP
var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a container to a snapshot by IP address",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ipAddressFlag == "" || snapshotNameFlag == "" {
			return cmd.Help()
		}

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
	},
}

func init() {
	restoreCmd.Flags().StringVar(&ipAddressFlag, "ip-address", "", "IPv4 address of the container to restore")
	restoreCmd.Flags().StringVar(&snapshotNameFlag, "snapshot-name", "", "Name of the snapshot to restore")
}
