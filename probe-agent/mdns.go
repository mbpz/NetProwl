package main

import (
	"log"

	"github.com/grandcat/zeroconf"
)

// startMdnsBroadcast advertises the agent service via mDNS on the local network.
func (a *Agent) startMdnsBroadcast() error {
	server, err := zeroconf.Register(
		"netprowl-agent",        // service name
		"_netprowl._tcp",        // service type
		"local.",                // domain
		a.config.ListenPort,     // port
		[]string{"version=1.0"}, // metadata
		nil,                    // interface index (nil = all interfaces)
	)
	if err != nil {
		return err
	}
	a.mdnsServer = server
	log.Printf("mDNS service _netprowl._tcp.local. advertised on port %d", a.config.ListenPort)
	return nil
}

// stopMdnsBroadcast stops the mDNS advertisement.
func (a *Agent) stopMdnsBroadcast() {
	if a.mdnsServer != nil {
		a.mdnsServer.Shutdown()
		a.mdnsServer = nil
		log.Println("mDNS broadcast stopped")
	}
}