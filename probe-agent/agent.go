package main

import (
	"fmt"
	"log"
	"net"

	"github.com/grandcat/zeroconf"
)

type Agent struct {
	config      *Config
	listener    net.Listener
	devices     map[string]*Device
	mdnsServer  *zeroconf.Server
}

type Device struct {
	IP       string
	MAC      string
	Hostname string
	Ports    []int
	OS       string
}

func NewAgent(cfg *Config) *Agent {
	return &Agent{
		config:  cfg,
		devices: make(map[string]*Device),
	}
}

func (a *Agent) Start() error {
	log.Printf("NetProwl Agent starting on :%d", a.config.ListenPort)
	if err := a.startMdnsBroadcast(); err != nil {
		log.Printf("mDNS broadcast failed (non-fatal): %v", err)
	}
	if err := a.startWebSocketServer(); err != nil {
		return fmt.Errorf("WebSocket server failed: %w", err)
	}
	return nil
}