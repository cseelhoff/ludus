package main

import (
	"context"
	"fmt"
	"log"
	ludusapi "ludusapi"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var inCluster bool
var remoteProxmoxMode bool

// detectRemoteProxmoxMode inspects CLI flags, environment variables, and any present
// config.yml (in ludusPath or /opt/ludus) before CPU virtualization or local pveversion
// checks execute.
func detectRemoteProxmoxMode() bool {
	if remoteProxmoxFlag {
		config.RemoteProxmox = true
		return true
	}
	if env := strings.ToLower(strings.TrimSpace(os.Getenv("LUDUS_REMOTE_PROXMOX"))); env == "1" || env == "true" || env == "yes" {
		config.RemoteProxmox = true
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
		if yaml.Unmarshal(raw, &probe) == nil && probe.RemoteProxmox {
			config = probe
			config.ApplyRemoteProxmoxDefaults()
			return true
		}
	}
	return false
}

// checkRemoteProxmox8or9 validates connectivity and Proxmox VE 8/9 version over HTTPS (:8006).
func checkRemoteProxmox8or9() {
	if strings.TrimSpace(config.ProxmoxURL) == "" || strings.Contains(config.ProxmoxURL, "127.0.0.1") || strings.Contains(config.ProxmoxURL, "localhost") {
		log.Fatal("remote_proxmox mode requires 'proxmox_url' in config.yml pointing to the outer Proxmox VE host (e.g. https://10.0.20.12:8006)")
	}
	if strings.TrimSpace(config.ProxmoxNode) == "" {
		log.Fatal("remote_proxmox mode requires 'proxmox_node' in config.yml set to a target Proxmox node name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ver, err := ludusapi.GetRemoteProxmoxVersion(ctx, &config)
	if err != nil {
		log.Fatalf("Unable to verify remote Proxmox VE API at %s: %v", config.ProxmoxURL, err)
	}
	if !strings.HasPrefix(ver, "8.") && !strings.HasPrefix(ver, "9.") && ver != "8" && ver != "9" {
		log.Fatalf("Remote Proxmox host reported unsupported version %q. Only Proxmox VE 8 or 9 are supported by Ludus.", ver)
	}
	log.Printf("Verified remote Proxmox VE %s at %s (node: %s, realm: %s)", ver, config.ProxmoxURL, config.ProxmoxNode, config.EffectiveProxmoxRealm())
}

// check for vmx or svm features in /proc/cpu with egrep. Will print a message and exit if they are not found.
func checkForVirtualizationSupport() {
	cpuInfo := Run("egrep '(vmx|svm)' --color=never /proc/cpuinfo", false, false)
	if !strings.Contains(cpuInfo, "vmx") && !strings.Contains(cpuInfo, "svm") {
		log.Fatal(`This machine is not capable of virtualization. 
Ludus is requires a host with vmx or svm enabled on the CPU. 
This is usually a bare metal machine or a nested VM with virtualization support enabled.
For Proxmox, see: https://pve.proxmox.com/wiki/Nested_Virtualization`)
	}
}

func generateConfigIfAutomatedInstall() {
	configPath := fmt.Sprintf("%s/config.yml", ludusPath)
	// First run, no config
	if ludusPath != fmt.Sprintf("%s/ludus-server", ludusInstallPath) && !fileExists(configPath) {
		// If we are running without prompts, generate a config automatically
		if autoGenerateConfig {
			log.Printf("No config.yml found. Generating a config at %s/config.yml. Please check that it contains the correct values.", ludusPath)
			automatedConfigGenerator(true)
		}
	}
}

// check the configuration file to ensure it exists and that it does not have default values
func checkConfig() {
	configPath := fmt.Sprintf("%s/config.yml", ludusPath)
	if !fileExists(configPath) && fileExists(fmt.Sprintf("%s/config.yml", ludusInstallPath)) {
		configPath = fmt.Sprintf("%s/config.yml", ludusInstallPath)
	}

	if ludusPath == fmt.Sprintf("%s/ludus-server", ludusInstallPath) && !fileExists(configPath) { // Installed, but config missing
		log.Printf("Config file (%s) missing!\n", configPath)
		os.Exit(1)
	}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		log.Fatalf("Error opening config: %v", err)
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	config.ProxmoxInvalidCert = true
	config.SSORequireExistingUser = true
	config.CreateDefaultRange = true
	if err := d.Decode(&config); err != nil {
		log.Fatalf("Error decoding config: %v", err)
	}
	if remoteProxmoxFlag {
		config.RemoteProxmox = true
	}
	config.ApplyRemoteProxmoxDefaults()

	if err := config.ApplyPortDefaultsAndValidate(); err != nil {
		log.Fatalf("%v", err)
	}
}

// check if the current uid is zero (root) and throw a fatal error if not
func checkRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("Ludus must be run as root.")
	}
}

func checkForProxmox8or9() bool {
	if fileExists("/usr/bin/pveversion") && !fileExists(fmt.Sprintf("%s/install/.installed-on-debian", ludusInstallPath)) {
		pveVersion := Run("pveversion", false, false)
		if strings.Contains(pveVersion, "pve-manager/8") {
			return true
		} else if strings.Contains(pveVersion, "pve-manager/9") {
			return true
		} else if strings.Contains(pveVersion, "pve-manager/7") {
			log.Fatal(`This is a Proxmox host but not proxmox 8 or 9.
Upgrade to Proxmox 8 or 9 before using Ludus.
See: https://pve.proxmox.com/wiki/Upgrade_from_7_to_8
`)
		} else {
			log.Fatal("This is a Proxmox host and is not a supported version. Only Proxmox 8 or 9 are supported by Ludus.")
		}
	}
	return false
}

// check /etc/os-release for Debian 12 or 13, throw a fatal error /etc/os-release does not exist or does not contain the Debian 12 string
func checkDebian12or13() {
	if fileExists("/etc/os-release") {
		osReleaseContents, err := os.ReadFile("/etc/os-release")
		if err != nil {
			log.Fatal(err.Error())
		}
		if !strings.Contains(string(osReleaseContents), "Debian GNU/Linux 12 (bookworm)") && !strings.Contains(string(osReleaseContents), "Debian GNU/Linux 13 (trixie)") {
			log.Fatal("/etc/os-release did not indicate this is Debian 12 or 13. Ludus only supports Debian 12 or 13.")
		}
	} else {
		log.Fatal("Could not read /etc/os-release to check for Debian 12 or 13. Ludus only supports Debian 12 or 13.")
	}
}

func isInCluster() bool {
	if remoteProxmoxMode || config.RemoteProxmox {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		clustered, err := ludusapi.IsRemoteProxmoxCluster(ctx, &config)
		if err != nil {
			logger.Debug(fmt.Sprintf("Could not determine remote cluster status prior to install: %v", err))
			return config.ClusterMode
		}
		return clustered
	}
	clusterStatus, err := RunWithOutput("ls -1 /etc/pve/nodes | wc -l")
	if err != nil || strings.Contains(clusterStatus, "ls: cannot access '/etc/pve/nodes'") {
		logger.Info("No cluster detected")
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(clusterStatus))
	if err != nil {
		logger.Error(fmt.Sprintf("Could not parse node count from cluster status: %v", err))
		return false
	}
	return n > 1
}
