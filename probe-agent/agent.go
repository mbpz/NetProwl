package main

import (
	"log"
	"net"
)

type Agent struct {
	config  *Config
	listener net.Listener
	devices  map[string]*Device
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
	return nil
}