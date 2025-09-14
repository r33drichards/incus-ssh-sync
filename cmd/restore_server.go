package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"incus-ssh-sync/pkg/incus"

	"github.com/spf13/cobra"
)

type restoreRequest struct {
	IP       string `json:"ip"`
	Snapshot string `json:"snapshot"`
}

var (
	restoreServerAddr     string
	restoreServerEndpoint string
	defaultSnapshotName   string
)

// restoreServerCmd starts a small HTTP server that listens for POST requests
// and triggers a restore by IP address.
var restoreServerCmd = &cobra.Command{
	Use:   "restore-server",
	Short: "Run HTTP server to restore instance by posted IP",
	RunE: func(cmd *cobra.Command, args []string) error {
		mux := http.NewServeMux()
		mux.HandleFunc(restoreServerEndpoint, handleRestoreByIP)

		srv := &http.Server{
			Addr:              restoreServerAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		if verbose {
			fmt.Printf("restore-server listening on %s%s (default snapshot=%q)\n", restoreServerAddr, restoreServerEndpoint, defaultSnapshotName)
		}

		return srv.ListenAndServe()
	},
}

func init() {
	restoreServerCmd.Flags().StringVar(&restoreServerAddr, "addr", ":8080", "address to listen on (host:port)")
	restoreServerCmd.Flags().StringVar(&restoreServerEndpoint, "path", "/return", "HTTP path to accept POST requests")
	restoreServerCmd.Flags().StringVar(&defaultSnapshotName, "default-snapshot", "preinstall", "fallback snapshot name if not provided in request")
}

func handleRestoreByIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, "method not allowed")
		return
	}

	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid json: %v", err)
		return
	}
	if req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "missing ip")
		return
	}

	servers, err := getServerConfigs()
	if err != nil {
		log.Printf("failed to load server configs: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "server config error")
		return
	}

	for _, server := range servers {
		client, err := incus.NewClientWithAuth(server.IncusSocket, server.IncusRemote, server.IncusRemoteURL, server.AuthToken)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[warn][%s] failed to connect: %v\n", server.ProxyJump, err)
			}
			continue
		}

		container, err := client.FindContainerByIP(req.IP)
		if err != nil {
			log.Printf("[%s] search containers failed: %v", server.ProxyJump, err)
			continue
		}
		if container == nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[%s] no container with IP %s\n", server.ProxyJump, req.IP)
			}
			continue
		}

		// choose snapshot: request > server config > CLI default
		snapshot := req.Snapshot
		if snapshot == "" {
			if server.RestoreSnapshot != "" {
				snapshot = server.RestoreSnapshot
			} else {
				snapshot = defaultSnapshotName
			}
		}

		if verbose {
			fmt.Printf("[%s] restoring %s to snapshot %s (IP: %s)\n", server.ProxyJump, container.Name, snapshot, req.IP)
		}
		if err := client.RestoreSnapshot(container.Name, snapshot); err != nil {
			log.Printf("[%s] restore failed for %s to %q: %v", server.ProxyJump, container.Name, snapshot, err)
			continue
		}

		// success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":    "ok",
			"container": container.Name,
			"snapshot":  snapshot,
		})
		return
	}

	// if we reach here, nothing matched
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "no container found for ip %s", req.IP)
}
