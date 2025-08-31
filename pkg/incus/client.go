package incus

import (
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
	socket    string
	remote    string
	remoteURL string
	authToken string
	httpClient *http.Client
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
			return nil, fmt.Errorf("failed to connect to remote Incus API at %s: %w\nNote: Remote connections require authentication. Please configure client certificates.", remoteURL, err)
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