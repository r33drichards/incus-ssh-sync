package incus

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	socket     string
	remote     string
	remoteURL  string
	authToken  string
	httpClient *http.Client
}

// extractOperationFailure inspects an Incus operation metadata object and
// returns a tuple of (failed, message, statusCode). It is defensive against
// shape variations by drilling into nested maps.
func extractOperationFailure(metadata interface{}) (bool, string, int) {
	// Defaults
	failed := false
	message := ""
	code := 0

	// Helper to convert arbitrary numeric to int
	toInt := func(v interface{}) int {
		switch n := v.(type) {
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case float64:
			return int(n)
		case float32:
			return int(n)
		default:
			return 0
		}
	}

	// Try top-level map
	if m, ok := metadata.(map[string]interface{}); ok {
		if v, ok := m["status_code"]; ok {
			code = toInt(v)
		}
		if v, ok := m["status"]; ok {
			if s, ok := v.(string); ok {
				if strings.EqualFold(s, "failure") || strings.EqualFold(s, "error") {
					failed = true
				}
				if message == "" {
					message = s
				}
			}
		}
		if v, ok := m["err"]; ok {
			if s, ok := v.(string); ok && s != "" {
				message = s
				failed = true
			}
		}
		// Also handle alternative fields used by Incus/LXD
		if v, ok := m["error"]; ok {
			if s, ok := v.(string); ok && s != "" {
				message = s
				failed = true
			}
		}
		if v, ok := m["error_code"]; ok && code == 0 {
			code = toInt(v)
		}
		// Sometimes details are nested under "metadata"
		if v, ok := m["metadata"]; ok && !failed {
			if mm, ok := v.(map[string]interface{}); ok {
				if ev, ok := mm["err"]; ok {
					if s, ok := ev.(string); ok && s != "" {
						message = s
						failed = true
					}
				}
				if ev, ok := mm["error"]; ok {
					if s, ok := ev.(string); ok && s != "" {
						message = s
						failed = true
					}
				}
				if sv, ok := mm["status"]; ok {
					if s, ok := sv.(string); ok {
						if strings.EqualFold(s, "failure") || strings.EqualFold(s, "error") {
							failed = true
						}
						if message == "" {
							message = s
						}
					}
				}
				if cv, ok := mm["status_code"]; ok && code == 0 {
					code = toInt(cv)
				}
				if cv, ok := mm["error_code"]; ok && code == 0 {
					code = toInt(cv)
				}
			}
		}
	}

	// If we still didn't conclusively determine failure, consider non-2xx codes as failure
	if !failed && code >= 400 {
		failed = true
	}

	return failed, message, code
}

type Container struct {
	Name      string
	IPAddress string
	Status    string
}

type APIResponse struct {
	Type       string      `json:"type"`
	Status     string      `json:"status"`
	StatusCode int         `json:"status_code"`
	Metadata   interface{} `json:"metadata"`
}

type InstanceState struct {
	Network map[string]NetworkInterface `json:"network"`
	Status  string                      `json:"status"`
}

type NetworkInterface struct {
	Addresses []NetworkAddress `json:"addresses"`
}

type NetworkAddress struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   string `json:"scope"`
}

func NewClient(socket, remote, remoteURL string) (*Client, error) {
	return NewClientWithAuth(socket, remote, remoteURL, "")
}

func NewClientWithAuth(socket, remote, remoteURL, authToken string) (*Client, error) {
	var httpClient *http.Client

	if remoteURL != "" {
		// HTTPS client for remote connections
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For self-signed certificates
				},
			},
		}
	} else {
		// Unix socket client for local connections
		// Check if socket exists
		if _, err := net.Dial("unix", socket); err != nil {
			return nil, fmt.Errorf("failed to connect to Incus socket %s: %w", socket, err)
		}

		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socket)
				},
			},
		}
	}

	client := &Client{
		socket:     socket,
		remote:     remote,
		remoteURL:  remoteURL,
		authToken:  authToken,
		httpClient: httpClient,
	}

	// Test connection by trying to reach the API
	if err := client.testConnection(); err != nil {
		// For remote connections, authentication might be required
		if remoteURL != "" {
			return nil, fmt.Errorf("failed to connect to remote Incus API at %s: %w Note: remote connections require authentication, please configure client certificates", remoteURL, err)
		}
		return nil, fmt.Errorf("failed to connect to Incus API: %w", err)
	}

	return client, nil
}

func (c *Client) testConnection() error {
	baseURL := c.getBaseURL()
	url := baseURL + "/1.0"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	c.addAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make test request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication required (status 401)")
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("API test failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) ListContainers(nameFilter, statusFilter string) ([]Container, error) {
	// Get list of instances
	instances, err := c.getInstances()
	if err != nil {
		return nil, fmt.Errorf("failed to get instances: %w", err)
	}

	var containers []Container
	for _, instance := range instances {
		// Apply name filter
		if nameFilter != "" && !strings.Contains(instance, nameFilter) {
			continue
		}

		// Get instance state to check status and get IP
		state, err := c.getInstanceState(instance)
		if err != nil {
			continue // Skip instances we can't get state for
		}

		// Apply status filter
		if statusFilter != "" && !strings.EqualFold(state.Status, statusFilter) {
			continue
		}

		// Extract IP address
		ipAddress := c.extractIPAddress(state)

		containers = append(containers, Container{
			Name:      instance,
			IPAddress: ipAddress,
			Status:    state.Status,
		})
	}

	return containers, nil
}

func (c *Client) getInstances() ([]string, error) {
	baseURL := c.getBaseURL()
	url := baseURL + "/1.0/instances"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %s", apiResp.Status)
	}

	// Extract instance names from metadata
	var instances []string

	// The metadata might be a direct list or contain an "instances" key
	if instanceList, ok := apiResp.Metadata.([]interface{}); ok {
		// Direct list format
		for _, item := range instanceList {
			if instanceURL, ok := item.(string); ok {
				// Extract instance name from URL path like "/1.0/instances/container-name"
				parts := strings.Split(instanceURL, "/")
				if len(parts) > 0 {
					instances = append(instances, parts[len(parts)-1])
				}
			}
		}
	} else if metadataMap, ok := apiResp.Metadata.(map[string]interface{}); ok {
		// Nested format
		if metadata, ok := metadataMap["instances"].([]interface{}); ok {
			for _, item := range metadata {
				if instanceURL, ok := item.(string); ok {
					// Extract instance name from URL path like "/1.0/instances/container-name"
					parts := strings.Split(instanceURL, "/")
					if len(parts) > 0 {
						instances = append(instances, parts[len(parts)-1])
					}
				}
			}
		}
	}

	return instances, nil
}

func (c *Client) getInstanceState(name string) (*InstanceState, error) {
	baseURL := c.getBaseURL()
	url := fmt.Sprintf("%s/1.0/instances/%s/state", baseURL, name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %s", apiResp.Status)
	}

	// Convert metadata to InstanceState
	metadataJSON, err := json.Marshal(apiResp.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var state InstanceState
	if err := json.Unmarshal(metadataJSON, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal instance state: %w", err)
	}

	return &state, nil
}

func (c *Client) extractIPAddress(state *InstanceState) string {
	// First priority: Look for eth0 interface with global scope
	if ethInterface, exists := state.Network["eth0"]; exists {
		for _, addr := range ethInterface.Addresses {
			if addr.Family == "inet" && addr.Scope == "global" && addr.Address != "127.0.0.1" {
				return addr.Address
			}
		}
	}

	// Second priority: Look for any non-Docker interface with global scope
	for interfaceName, netInterface := range state.Network {
		// Skip Docker-related interfaces
		if strings.HasPrefix(interfaceName, "docker") ||
			strings.HasPrefix(interfaceName, "br-") ||
			interfaceName == "lo" {
			continue
		}

		for _, addr := range netInterface.Addresses {
			if addr.Family == "inet" && addr.Scope == "global" && addr.Address != "127.0.0.1" {
				return addr.Address
			}
		}
	}

	// Fallback: Any IPv4 address, excluding Docker interfaces
	for interfaceName, netInterface := range state.Network {
		// Skip Docker-related interfaces in fallback too
		if strings.HasPrefix(interfaceName, "docker") ||
			strings.HasPrefix(interfaceName, "br-") ||
			interfaceName == "lo" {
			continue
		}

		for _, addr := range netInterface.Addresses {
			if addr.Family == "inet" && addr.Address != "127.0.0.1" {
				return addr.Address
			}
		}
	}

	return ""
}

func (c *Client) addAuth(req *http.Request) {
	if c.authToken != "" && c.remoteURL != "" {
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: c.authToken,
		})
	}
}

func (c *Client) getBaseURL() string {
	if c.remoteURL != "" {
		return c.remoteURL
	}
	return "http://unix"
}

// FindContainerByIP returns the first container whose extracted IPv4 address
// matches the provided ipAddress. Returns nil if no match is found.
func (c *Client) FindContainerByIP(ipAddress string) (*Container, error) {
	if ipAddress == "" {
		return nil, fmt.Errorf("ip address must not be empty")
	}

	containers, err := c.ListContainers("", "")
	if err != nil {
		return nil, err
	}

	for _, container := range containers {
		if container.IPAddress == ipAddress {
			// Return the first exact match
			copy := container
			return &copy, nil
		}
	}

	return nil, nil
}

// RestoreSnapshot restores the specified instance to the given snapshot name.
// It triggers the restore operation and waits for completion.
func (c *Client) RestoreSnapshot(instanceName, snapshotName string) error {
	if instanceName == "" || snapshotName == "" {
		return fmt.Errorf("instance name and snapshot name must be provided")
	}

	// If the instance is running, stop it first (non-stateful restore requires stopped instance)
	state, err := c.getInstanceState(instanceName)
	if err != nil {
		return fmt.Errorf("failed to get instance state: %w", err)
	}
	wasRunning := false
	if state != nil && strings.EqualFold(state.Status, "running") {
		wasRunning = true
		if err := c.changeInstanceState(instanceName, "stop", 120, true); err != nil {
			return fmt.Errorf("failed to stop instance before restore: %w", err)
		}
	}

	baseURL := c.getBaseURL()

	// Try explicit snapshot restore endpoint first
	restoreURL := fmt.Sprintf("%s/1.0/instances/%s/snapshots/%s/restore", baseURL, instanceName, snapshotName)
	if err := c.doOperationRequest("POST", restoreURL, map[string]interface{}{}); err != nil {
		// Fallback to PUT restore field if the explicit endpoint isn't available or fails
		fallbackURL := fmt.Sprintf("%s/1.0/instances/%s", baseURL, instanceName)
		fallbackPayload := map[string]interface{}{"restore": snapshotName}
		if err2 := c.doOperationRequest("PUT", fallbackURL, fallbackPayload); err2 != nil {
			return fmt.Errorf("restore failed (explicit endpoint error: %v, fallback error: %v)", err, err2)
		}
	}

	// Start the instance again if we stopped it
	if wasRunning {
		if err := c.changeInstanceState(instanceName, "start", 120, false); err != nil {
			return fmt.Errorf("restore succeeded but failed to start instance: %w", err)
		}
	}
	return nil
}

// waitForOperation waits for the given operation URL (absolute or relative)
// to complete successfully.
func (c *Client) waitForOperation(operationURL string) error {
	// Build absolute URL if needed
	if strings.HasPrefix(operationURL, "/") {
		operationURL = c.getBaseURL() + operationURL
	}

	// Append /wait to block until completion
	waitURL := operationURL + "/wait"

	req, err := http.NewRequest("GET", waitURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create wait request: %w", err)
	}
	c.addAuth(req)

	// Use a no-timeout client for long-running waits
	noTimeoutClient := *c.httpClient
	noTimeoutClient.Timeout = 0

	resp, err := noTimeoutClient.Do(req)
	if err != nil {
		return fmt.Errorf("operation wait failed: %w", err)
	}
	defer resp.Body.Close()

	var waitResp struct {
		Type       string      `json:"type"`
		Status     string      `json:"status"`
		StatusCode int         `json:"status_code"`
		Metadata   interface{} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&waitResp); err != nil {
		return fmt.Errorf("failed to decode wait response: %w", err)
	}

	// Prefer operation metadata details when available
	if waitResp.Metadata != nil {
		failed, msg, code := extractOperationFailure(waitResp.Metadata)
		if failed {
			if msg == "" {
				msg = waitResp.Status
			}
			return fmt.Errorf("operation failed: %s (code %d)", msg, code)
		}
	}

	// If metadata isn't available, best-effort fallback to top-level status
	if strings.EqualFold(waitResp.Status, "failure") || strings.EqualFold(waitResp.Status, "error") {
		return fmt.Errorf("operation failed: %s", waitResp.Status)
	}

	return nil
}

// doOperationRequest sends an HTTP request that triggers an Incus operation and waits for completion.
func (c *Client) doOperationRequest(method, url string, payload interface{}) error {
	var bodyReader *bytes.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to encode request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader([]byte("{}"))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var opResp struct {
		Type       string      `json:"type"`
		Status     string      `json:"status"`
		StatusCode int         `json:"status_code"`
		Operation  string      `json:"operation"`
		Metadata   interface{} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if opResp.Metadata != nil {
			failed, msg, code := extractOperationFailure(opResp.Metadata)
			if failed {
				if code == 0 {
					code = resp.StatusCode
				}
				if msg != "" {
					return fmt.Errorf("API error: %s (code %d)", msg, code)
				}
			}
		}
		return fmt.Errorf("API error: %s (code %d)", opResp.Status, resp.StatusCode)
	}

	if opResp.Operation != "" {
		return c.waitForOperation(opResp.Operation)
	}
	return nil
}

// changeInstanceState sends an action to the instance state endpoint and waits for completion.
func (c *Client) changeInstanceState(instanceName, action string, timeoutSeconds int, force bool) error {
	baseURL := c.getBaseURL()
	url := fmt.Sprintf("%s/1.0/instances/%s/state", baseURL, instanceName)

	body := map[string]interface{}{
		"action":   action,
		"timeout":  timeoutSeconds,
		"force":    force,
		"stateful": false,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to encode state request: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to create state request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("state change request failed: %w", err)
	}
	defer resp.Body.Close()

	var opResp struct {
		Type       string      `json:"type"`
		Status     string      `json:"status"`
		StatusCode int         `json:"status_code"`
		Operation  string      `json:"operation"`
		Metadata   interface{} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opResp); err != nil {
		return fmt.Errorf("failed to decode state change response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if opResp.Metadata != nil {
			failed, msg, code := extractOperationFailure(opResp.Metadata)
			if failed {
				if code == 0 {
					code = resp.StatusCode
				}
				if msg != "" {
					return fmt.Errorf("API error: %s (code %d)", msg, code)
				}
			}
		}
		return fmt.Errorf("API error: %s (code %d)", opResp.Status, resp.StatusCode)
	}

	if opResp.Operation != "" {
		return c.waitForOperation(opResp.Operation)
	}
	return nil
}
