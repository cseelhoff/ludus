package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ludusapi/edgeproxy"
)

func main() {
	var (
		listenAddr   string
		stateDir     string
		enrollPub    string
		enrollPubPath string
		natBindIP    string
		portMin      uint
		portMax      uint
		wgQuickHook  bool
	)
	flag.StringVar(&listenAddr, "listen", "0.0.0.0:8444", "TLS 1.3 listen address")
	flag.StringVar(&stateDir, "state-dir", "/var/lib/ludus-edge", "persistent private 0600 seal state directory")
	flag.StringVar(&enrollPub, "enroll-pubkey", "", "base64 Ed25519 enrollment public key")
	flag.StringVar(&enrollPubPath, "enroll-pubkey-file", "/var/lib/ludus-edge/enroll.pub", "path to Ed25519 enrollment public key from cloud-init")
	flag.StringVar(&natBindIP, "nat-bind-ip", edgeproxy.DefaultEdgeNATIP, "ludusnat IP for reverse Packer HTTP listeners")
	flag.UintVar(&portMin, "packer-port-min", edgeproxy.DefaultPackerPortMin, "minimum reverse Packer HTTP port")
	flag.UintVar(&portMax, "packer-port-max", edgeproxy.DefaultPackerPortMax, "maximum reverse Packer HTTP port")
	flag.BoolVar(&wgQuickHook, "wg-quick", true, "write /etc/wireguard/wg0.conf and bring up wg0 on seal")
	flag.Parse()

	if strings.TrimSpace(enrollPub) == "" {
		candidates := []string{
			strings.TrimSpace(enrollPubPath),
			"/home/ludus-edge/.ssh/authorized_keys",
			"/root/.ssh/authorized_keys",
		}
		for _, candidate := range candidates {
			if candidate == "" {
				continue
			}
			if b, err := os.ReadFile(candidate); err == nil {
				if parsed, pErr := edgeproxy.ParseEnrollSSHAuthorizedKey(string(b)); pErr == nil {
					enrollPub = parsed
					break
				}
			}
		}
	} else if parsed, pErr := edgeproxy.ParseEnrollSSHAuthorizedKey(enrollPub); pErr == nil {
		enrollPub = parsed
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := edgeproxy.NewServer(edgeproxy.ServerConfig{
		ListenAddr:        listenAddr,
		StateDir:          stateDir,
		EnrollPublicB64:   enrollPub,
		NATBindIP:         natBindIP,
		PackerPortMin:     uint16(portMin),
		PackerPortMax:     uint16(portMax),
		EnableWGQuickHook: wgQuickHook,
		Logger:            logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize ludus-edge-proxy: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start ludus-edge-proxy: %v\n", err)
		os.Exit(1)
	}
	logger.Info("ludus-edge-proxy started", "addr", srv.Addr(), "sealed", srv.IsSealed(), "nat_bind_ip", natBindIP)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutting down ludus-edge-proxy")
	_ = srv.Close()
}
