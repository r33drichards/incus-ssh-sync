package ssh

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Hosts                  map[string]*HostEntry
	Lines                  []string
	DisableHostKeyChecking bool
}

type HostEntry struct {
	Name      string
	HostName  string
	ProxyJump string
	User      string
}

func ReadConfig(path string) (*Config, error) {
	config := &Config{
		Hosts: make(map[string]*HostEntry),
		Lines: []string{},
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, fmt.Errorf("failed to open SSH config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentHost *HostEntry

	for scanner.Scan() {
		line := scanner.Text()
		config.Lines = append(config.Lines, line)

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		switch key {
		case "host":
			if currentHost != nil {
				config.Hosts[currentHost.Name] = currentHost
			}
			currentHost = &HostEntry{Name: value}
		case "hostname":
			if currentHost != nil {
				currentHost.HostName = value
			}
		case "proxyjump":
			if currentHost != nil {
				currentHost.ProxyJump = value
			}
		case "user":
			if currentHost != nil {
				currentHost.User = value
			}
		}
	}

	if currentHost != nil {
		config.Hosts[currentHost.Name] = currentHost
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSH config: %w", err)
	}

	return config, nil
}

func WriteConfig(config *Config, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create SSH config file: %w", err)
	}
	defer file.Close()

	for _, host := range config.Hosts {
		fmt.Fprintf(file, "\nHost %s\n", host.Name)
		if host.HostName != "" {
			fmt.Fprintf(file, "    HostName %s\n", host.HostName)
		}
		if host.User != "" {
			fmt.Fprintf(file, "    User %s\n", host.User)
		}
		if host.ProxyJump != "" {
			fmt.Fprintf(file, "    ProxyJump %s\n", host.ProxyJump)
		}
		if config.DisableHostKeyChecking {
			fmt.Fprintf(file, "    StrictHostKeyChecking no\n")
			fmt.Fprintf(file, "    UserKnownHostsFile /dev/null\n")
		}
	}

	return nil
}

func BackupConfig(src, dst string) error {
	// TODO: Implement config backup
	return fmt.Errorf("not implemented")
}

func HostExists(config *Config, name string) bool {
	_, exists := config.Hosts[name]
	return exists
}

func GetHostIP(config *Config, name string) string {
	host, exists := config.Hosts[name]
	if !exists {
		return ""
	}
	return host.HostName
}

func AddHost(config *Config, entry HostEntry) error {
	config.Hosts[entry.Name] = &entry
	return nil
}

func UpdateHost(config *Config, entry HostEntry) error {
	config.Hosts[entry.Name] = &entry
	return nil
}

func RemoveHost(config *Config, name string) error {
	delete(config.Hosts, name)
	return nil
}

func GetAllHosts(config *Config) []string {
	hosts := make([]string, 0, len(config.Hosts))
	for name := range config.Hosts {
		hosts = append(hosts, name)
	}
	return hosts
}
