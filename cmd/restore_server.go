package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
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
		mux.HandleFunc("/operations/status", handleGetStatus)
		mux.HandleFunc("/operations/events", handleSSE)

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
		// async execution
		opID := newOp(container.Name, req.IP, snapshot)
		go func(op string, c *incus.Client, containerName, snap, proxy string) {
			updateOp(op, "in_progress", fmt.Sprintf("restoring %s", containerName))
			if err := c.RestoreSnapshot(containerName, snap); err != nil {
				log.Printf("[%s] restore failed for %s to %q: %v", proxy, containerName, snap, err)
				updateOp(op, "failed", err.Error())
				return
			}
			updateOp(op, "succeeded", "completed")
		}(opID, client, container.Name, snapshot, server.ProxyJump)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"operation_id": opID,
			"status":       "accepted",
		})
		return
	}

	// if we reach here, nothing matched
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "no container found for ip %s", req.IP)
}

// ---- in-memory operation tracking + SSE ----

type opState struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	IP      string `json:"ip"`
	Target  string `json:"target"`
}

var (
	opsMu   sync.RWMutex
	ops     = map[string]opState{}
	sseMu   sync.RWMutex
	sseSubs = map[string][]chan string{}
)

func newOp(target, ip, snapshot string) string {
	id := fmt.Sprintf("op_%d_%d", time.Now().UnixNano(), rand.Int())
	opsMu.Lock()
	ops[id] = opState{Status: "pending", Message: "created", IP: ip, Target: target}
	opsMu.Unlock()
	broadcast(id, `{"event":"created"}`)
	return id
}

func updateOp(id, status, msg string) {
	opsMu.Lock()
	st := ops[id]
	st.Status = status
	st.Message = msg
	ops[id] = st
	opsMu.Unlock()
	payload := fmt.Sprintf("{\"event\":\"%s\",\"message\":%q}", status, msg)
	broadcast(id, payload)
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "missing id")
		return
	}
	opsMu.RLock()
	st, ok := ops[id]
	opsMu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"operation_id": id,
		"status":       st.Status,
		"message":      st.Message,
	})
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "missing id")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 16)
	subscribe(id, ch)
	defer unsubscribe(id, ch)

	if f, ok := w.(http.Flusher); ok {
		fmt.Fprintf(w, "event: ping\n")
		fmt.Fprintf(w, "data: \n\n")
		f.Flush()
	}

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

func subscribe(id string, ch chan string) {
	sseMu.Lock()
	sseSubs[id] = append(sseSubs[id], ch)
	sseMu.Unlock()
}

func unsubscribe(id string, ch chan string) {
	sseMu.Lock()
	subs := sseSubs[id]
	out := subs[:0]
	for _, c := range subs {
		if c != ch {
			out = append(out, c)
		}
	}
	sseSubs[id] = out
	sseMu.Unlock()
}

func broadcast(id, payload string) {
	sseMu.RLock()
	subs := append([]chan string(nil), sseSubs[id]...)
	sseMu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- payload:
		default:
		}
	}
}
