package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "get-url [proxy_jump ...]",
	Short: "Print Incus Web UI URLs by proxy_jump (defaults to all)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGetURL(cmd, args)
	},
}

func init() {
	// Add any flags specific to get-url command here
	connectCmd.Flags().String("proxy-jump", "", "ProxyJump to include in the URL output (deprecated, use arg)")
}

func execWithSession(client *ssh.Client, command string, debug bool) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	if debug {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}
	return session.CombinedOutput(command)
}

func runGetURL(cmd *cobra.Command, args []string) error {
	// Backward-compatible single proxy-jump flag
	if cmd.Flags().Changed("proxy-jump") && len(args) == 0 {
		if v, err := cmd.Flags().GetString("proxy-jump"); err == nil && v != "" {
			args = []string{v}
		}
	}

	servers, err := findServersByProxyJumps(args)
	if err != nil {
		return err
	}

	for _, server := range servers {
		username := server.DefaultUser
		if username == "" {
			if u := os.Getenv("USER"); u != "" {
				username = u
			} else {
				username = "root"
			}
		}

		authMethods, err := buildSSHAuthMethods()
		if err != nil {
			return err
		}

		addr := server.ProxyJump
		if !strings.Contains(server.ProxyJump, ":") {
			addr = net.JoinHostPort(server.ProxyJump, "22")
		}

		// Host key policy per server
		skipHostKey := server.SkipHostKeyCheck
		var hostKeyCallback ssh.HostKeyCallback
		if skipHostKey {
			hostKeyCallback = ssh.InsecureIgnoreHostKey()
		} else {
			// Use user's known_hosts if available
			home, _ := os.UserHomeDir()
			knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
			kh, khErr := knownhosts.New(knownHostsPath)
			if khErr != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "[debug] failed to load known_hosts from %s: %v; falling back to insecure host key policy\n", knownHostsPath, khErr)
				}
				hostKeyCallback = ssh.InsecureIgnoreHostKey()
			} else {
				hostKeyCallback = kh
			}
		}

		clientConfig := &ssh.ClientConfig{
			User:            username,
			Auth:            authMethods,
			HostKeyCallback: hostKeyCallback,
			Timeout:         10 * time.Second,
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[debug] server=%s user=%s skip_host_key_check=%t\n", server.ProxyJump, username, skipHostKey)
			fmt.Fprintf(os.Stderr, "[debug] auth methods configured: %d\n", len(authMethods))
			fmt.Fprintf(os.Stderr, "[debug] dialing ssh tcp %s as %s (timeout=%s)\n", addr, username, clientConfig.Timeout)
		}

		// Add banner callback to capture Tailscale authentication messages
		clientConfig.BannerCallback = func(message string) error {
			fmt.Fprint(os.Stderr, message)
			return nil
		}

		// Establish TCP connection with timeout and perform SSH handshake with deadline
		dialTimeout := 5 * time.Second
		rawConn, dErr := net.DialTimeout("tcp", addr, dialTimeout)
		if dErr != nil {
			return fmt.Errorf("[%s] TCP connect to %s failed within %s: %w", server.ProxyJump, addr, dialTimeout, dErr)
		}
		defer func() {
			// In case handshake fails, ensure TCP socket is closed
			_ = rawConn.Close()
		}()
		_ = rawConn.SetDeadline(time.Now().Add(clientConfig.Timeout))

		conn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, clientConfig)
		if err != nil {
			return fmt.Errorf("[%s] SSH handshake to %s failed: %w", server.ProxyJump, addr, err)
		}
		client := ssh.NewClient(conn, chans, reqs)
		defer client.Close()

		if debug {
			fmt.Fprintln(os.Stderr, "[debug] ssh connection established")
		}

		_, err = execWithSession(client, "sudo systemctl restart incus-webui.service", debug)
		if err != nil {
			return fmt.Errorf("[%s] remote command failed: %w", server.ProxyJump, err)
		}

		_, err = execWithSession(client, "sudo systemctl restart tailscale-serve.service", debug)
		if err != nil {
			return fmt.Errorf("[%s] remote command failed: %w", server.ProxyJump, err)
		}

		out, err := execWithSession(client, "sudo journalctl -xeu incus-webui.service -r", debug)
		if err != nil {
			return fmt.Errorf("[%s] remote command failed: %w", server.ProxyJump, err)
		}
		url, err := getUrl(string(out))
		if err != nil {
			return fmt.Errorf("[%s] failed to get url: %w", server.ProxyJump, err)
		}
		if url == nil {
			return fmt.Errorf("[%s] no url found in output", server.ProxyJump)
		}
		substitutedUrl, err := substituteUrlWithIncusRemoteUrlForServer(*url, server)
		if err != nil {
			return fmt.Errorf("[%s] failed to substitute url: %w", server.ProxyJump, err)
		}
		if substitutedUrl == nil {
			return fmt.Errorf("[%s] no substituted url found", server.ProxyJump)
		}
		fmt.Println(*substitutedUrl)
	}

	return nil
}

func substituteUrlWithIncusRemoteUrlForServer(url string, server ServerConfig) (*string, error) {
	parts := strings.Split(url, "http://127.0.0.1:")[1]
	pathStart := strings.Index(parts, "/")
	if pathStart == -1 {
		return nil, fmt.Errorf("invalid URL format: no path found")
	}
	path := parts[pathStart:]

	host := server.IncusRemoteURL
	if host == "" {
		return nil, fmt.Errorf("incus_remote_url is not set")
	}
	url = host + path
	return &url, nil
}

func getUrl(out string) (*string, error) {
	prefix := "http://127.0.0.1:"
	var match *string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, prefix) {
			match = &line
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no match found")
	}

	onlyUrl := strings.Split(*match, prefix)[1]
	theUrl := prefix + onlyUrl
	return &theUrl, nil
}

func buildSSHAuthMethods() ([]ssh.AuthMethod, error) {
	methods := []ssh.AuthMethod{}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}

	home, _ := os.UserHomeDir()
	keyCandidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
	for _, keyPath := range keyCandidates {
		if pem, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(pem); err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
			}
		}
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available (agent or private key)")
	}
	return methods, nil
}
