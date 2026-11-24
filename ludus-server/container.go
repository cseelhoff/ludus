package main

import (
	"context"
	"fmt"
	"log"
	ludusapi "ludusapi"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

var containerMode bool

// detectContainerMode inspects CLI flags, LUDUS_CONTAINER_MODE, and config.yml
// to determine whether Ludus is running in unprivileged OCI container mode.
func detectContainerMode() bool {
	if containerFlag || adminServerFlag || userServerFlag {
		if containerFlag {
			config.ContainerMode = true
			return true
		}
	}
	if env := strings.ToLower(strings.TrimSpace(os.Getenv("LUDUS_CONTAINER_MODE"))); env == "1" || env == "true" || env == "yes" {
		config.ContainerMode = true
		return true
	}
	candidatePaths := []string{
		fmt.Sprintf("%s/config.yml", ludusPath),
		fmt.Sprintf("%s/config.yml", ludusInstallPath),
	}
	for _, p := range candidatePaths {
		if !fileExists(p) {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var probe ludusapi.Configuration
		probe.ProxmoxInvalidCert = true
		probe.SSORequireExistingUser = true
		probe.CreateDefaultRange = true
		if yaml.Unmarshal(raw, &probe) == nil && probe.ContainerMode {
			config = probe
			config.ApplyRemoteProxmoxDefaults()
			return true
		}
	}
	return false
}

func seedContainerInitialAdminFromEnv() error {
	userID := strings.TrimSpace(os.Getenv("LUDUS_ADMIN_USER_ID"))
	if userID == "" {
		return nil
	}
	initialAdminMarker := filepath.Join(ludusInstallPath, "install", "initial-admin-userid")
	initialAdminPath := filepath.Join(ludusInstallPath, "install", "initial-admin.yml")
	if fileExists(initialAdminMarker) || fileExists(initialAdminPath) {
		return nil
	}

	password := os.Getenv("LUDUS_ADMIN_PASSWORD")
	if pwFile := strings.TrimSpace(os.Getenv("LUDUS_ADMIN_PASSWORD_FILE")); pwFile != "" {
		raw, err := os.ReadFile(pwFile)
		if err != nil {
			return fmt.Errorf("reading LUDUS_ADMIN_PASSWORD_FILE %q: %w", pwFile, err)
		}
		password = strings.TrimRight(string(raw), "\r\n")
	}
	if password == "" {
		return fmt.Errorf("LUDUS_ADMIN_USER_ID (%s) is set, but LUDUS_ADMIN_PASSWORD / LUDUS_ADMIN_PASSWORD_FILE is empty", userID)
	}

	name := strings.TrimSpace(os.Getenv("LUDUS_ADMIN_NAME"))
	if name == "" {
		name = userID
	}
	email := strings.TrimSpace(os.Getenv("LUDUS_ADMIN_EMAIL"))

	payload := struct {
		Name     string `yaml:"name"`
		UserID   string `yaml:"user_id"`
		Password string `yaml:"password"`
		Email    string `yaml:"email,omitempty"`
	}{
		Name:     name,
		UserID:   userID,
		Password: password,
		Email:    email,
	}
	encoded, err := yaml.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshaling initial-admin.yml: %w", err)
	}
	if err := os.WriteFile(initialAdminPath, encoded, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", initialAdminPath, err)
	}
	return nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func bootstrapContainerEnvironment() {
	checkConfig()
	config.ContainerMode = true
	config.ApplyRemoteProxmoxDefaults()

	dataDir := strings.TrimSpace(config.DataDirectory)
	if dataDir == "" {
		dataDir = filepath.Join(ludusInstallPath, "db")
	}
	requiredDirs := []string{
		dataDir,
		filepath.Join(dataDir, "storage"),
		config.EdgeStateDir,
		filepath.Join(ludusInstallPath, "install"),
		filepath.Join(ludusInstallPath, "ranges"),
		filepath.Join(ludusInstallPath, "users", "root", ".ansible", "roles"),
		filepath.Join(ludusInstallPath, "users", "root", ".ansible", "collections"),
		filepath.Join(ludusInstallPath, "sources"),
		filepath.Join(ludusInstallPath, "blueprints"),
		filepath.Join(ludusInstallPath, "resources", "global-roles"),
		filepath.Join(ludusInstallPath, "resources", "global-collections"),
		filepath.Join(ludusInstallPath, "ansible", "tmp"),
	}
	for _, dir := range requiredDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0770); err != nil {
			log.Fatalf("Failed to create container runtime directory %s: %v", dir, err)
		}
	}

	if !fileExists(filepath.Join(ludusInstallPath, "ansible", "range-management", "ludus.yml")) {
		extractDirectory(embeddedAnsbileDir, "ansible")
		_ = os.Chmod(filepath.Join(ludusInstallPath, "ansible", "range-management", "dynamic-inventory"), 0755)
	}
	if !dirExists(filepath.Join(ludusInstallPath, "packer")) {
		extractDirectory(embeddedPackerDir, "packer")
	}
	if !dirExists(filepath.Join(ludusInstallPath, "ci")) {
		extractDirectory(embeddedCIDir, "ci")
	}

	stage3Marker := filepath.Join(ludusInstallPath, "install", ".stage-3-complete")
	if !fileExists(stage3Marker) {
		if err := os.WriteFile(stage3Marker, []byte("container\n"), 0644); err != nil {
			log.Fatalf("Failed to write %s: %v", stage3Marker, err)
		}
	}

	if err := seedContainerInitialAdminFromEnv(); err != nil {
		log.Fatalf("Failed to seed initial admin configuration: %v", err)
	}

	checkRemoteProxmox8or9()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := ludusapi.BootstrapRemoteProxmox(ctx, &config); err != nil {
		log.Fatalf("Proxmox startup verification/bootstrap failed: %v", err)
	}
}

func waitForTCPReady(addr string, timeout time.Duration, childDone <-chan error) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-childDone:
			return fmt.Errorf("admin server exited before becoming ready on %s: %w", addr, err)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for admin server on %s", timeout, addr)
}

// runContainerSupervisor runs both the unprivileged ludus-admin server
// (127.0.0.1:8081) and the user-facing ludus server (0.0.0.0:8080) as managed
// child processes, waiting for admin migrations/InitDb readiness first.
func runContainerSupervisor() {
	bootstrapContainerEnvironment()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Unable to resolve ludus-server executable: %v", err)
	}

	baseEnv := append(os.Environ(), "LUDUS_CONTAINER_MODE=true")

	adminArgs := []string{"--admin"}
	userArgs := []string{"--user-server"}
	if debugFlag {
		adminArgs = append(adminArgs, "--debug")
		userArgs = append(userArgs, "--debug")
	}

	adminCmd := exec.Command(exePath, adminArgs...)
	adminCmd.Stdout = os.Stdout
	adminCmd.Stderr = os.Stderr
	adminCmd.Env = baseEnv
	if err := adminCmd.Start(); err != nil {
		log.Fatalf("Failed to start ludus-admin child process: %v", err)
	}
	adminDone := make(chan error, 1)
	go func() {
		adminDone <- adminCmd.Wait()
	}()

	adminAddr := fmt.Sprintf("127.0.0.1:%d", config.AdminPort)
	if err := waitForTCPReady(adminAddr, 45*time.Second, adminDone); err != nil {
		if adminCmd.Process != nil {
			_ = adminCmd.Process.Signal(syscall.SIGTERM)
		}
		log.Fatalf("Container startup failed: %v", err)
	}
	log.Printf("ludus-admin ready on %s; starting user API server on 0.0.0.0:%d", adminAddr, config.Port)

	userCmd := exec.Command(exePath, userArgs...)
	userCmd.Stdout = os.Stdout
	userCmd.Stderr = os.Stderr
	userCmd.Env = baseEnv
	if err := userCmd.Start(); err != nil {
		_ = adminCmd.Process.Signal(syscall.SIGTERM)
		log.Fatalf("Failed to start ludus user-server child process: %v", err)
	}
	userDone := make(chan error, 1)
	go func() {
		userDone <- userCmd.Wait()
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	terminateBoth := func(sig os.Signal) {
		if userCmd.Process != nil {
			_ = userCmd.Process.Signal(sig)
		}
		if adminCmd.Process != nil {
			_ = adminCmd.Process.Signal(sig)
		}
	}

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s; shutting down ludus and ludus-admin...", sig)
		terminateBoth(sig)
		shutdownTimer := time.NewTimer(10 * time.Second)
		defer shutdownTimer.Stop()
		for remaining := 2; remaining > 0; {
			select {
			case <-adminDone:
				adminDone = nil
				remaining--
			case <-userDone:
				userDone = nil
				remaining--
			case <-shutdownTimer.C:
				if userCmd.Process != nil {
					_ = userCmd.Process.Kill()
				}
				if adminCmd.Process != nil {
					_ = adminCmd.Process.Kill()
				}
				os.Exit(0)
			}
		}
		os.Exit(0)
	case err := <-adminDone:
		log.Printf("ludus-admin exited unexpectedly (%v); stopping user server", err)
		if userCmd.Process != nil {
			_ = userCmd.Process.Signal(syscall.SIGTERM)
		}
		<-userDone
		os.Exit(1)
	case err := <-userDone:
		log.Printf("ludus user server exited unexpectedly (%v); stopping admin server", err)
		if adminCmd.Process != nil {
			_ = adminCmd.Process.Signal(syscall.SIGTERM)
		}
		<-adminDone
		os.Exit(1)
	}
}
