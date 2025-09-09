package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "get-url",
	Short: "Connect to an Incus container",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGetURL(cmd, args)
	},
}

func init() {
	// Add any flags specific to get-url command here
	connectCmd.Flags().String("proxy-jump", "", "ProxyJump to include in the URL output")
}

func runGetURL(cmd *cobra.Command, args []string) error {
	proxyJump := viper.GetString("proxy_jump")
	if cmd.Flags().Changed("proxy-jump") {
		if v, err := cmd.Flags().GetString("proxy-jump"); err == nil {
			proxyJump = v
		}
	}
	if proxyJump == "" {
		return fmt.Errorf("proxy_jump is not set")
	}

	username := viper.GetString("default_user")
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

	addr := proxyJump
	if !strings.Contains(proxyJump, ":") {
		addr = net.JoinHostPort(proxyJump, "22")
	}

	// Host key policy
	skipHostKey := viper.GetBool("skip_host_key_check")
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
		fmt.Fprintf(os.Stderr, "[debug] config: proxy_jump=%s user=%s skip_host_key_check=%t\n", proxyJump, username, skipHostKey)
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
		return fmt.Errorf("TCP connect to %s failed within %s: %w", addr, dialTimeout, dErr)
	}
	defer func() {
		// In case handshake fails, ensure TCP socket is closed
		_ = rawConn.Close()
	}()
	_ = rawConn.SetDeadline(time.Now().Add(clientConfig.Timeout))

	conn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, clientConfig)
	if err != nil {
		return fmt.Errorf("SSH handshake to %s failed: %w", addr, err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	if debug {
		fmt.Fprintln(os.Stderr, "[debug] ssh connection established")
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create ssh session: %w", err)
	}
	defer session.Close()

	if debug {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}

	if debug {
		fmt.Fprintln(os.Stderr, "[debug] running remote probe command")
	}
	out, err := session.CombinedOutput("sudo journalctl -xeu incus-webui.service -r")
	if err != nil {
		return fmt.Errorf("remote command failed: %w", err)
	}
	url, err := getUrl(string(out))
	if err != nil {
		return fmt.Errorf("failed to get url: %w", err)
	}
	if url == nil {
		return fmt.Errorf("no url found in output")
	}
	substitutedUrl, err := substituteUrlWithIncusRemoteUrl(*url)
	if err != nil {
		return fmt.Errorf("failed to substitute url: %w", err)
	}
	if substitutedUrl == nil {
		return fmt.Errorf("no substituted url found")
	}
	fmt.Println(*substitutedUrl)

	return nil
}

// incoming url: http://127.0.0.1:38155/ui?auth_token=259f7921-0de5-44ee-b196-57046e5912cd
// outgoing url: https://incus-1.camel-kitchen.ts.net/ui?auth_token=259f7921-0de5-44ee-b196-57046e5912cd

func substituteUrlWithIncusRemoteUrl(url string) (*string, error) {
	// remove  http://127.0.0.1:* from the url
	parts := strings.Split(url, "http://127.0.0.1:")[1]
	// extract path after port number
	pathStart := strings.Index(parts, "/")
	if pathStart == -1 {
		return nil, fmt.Errorf("invalid URL format: no path found")
	}
	path := parts[pathStart:]

	host := viper.GetString("incus_remote_url")
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
