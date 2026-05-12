// Package core provides network scanning capabilities.
package core

import (
    "context"

    "github.com/netprowl/core/scanner"
    "github.com/netprowl/core/util"
)

// Device represents a discovered network device.
type Device = scanner.Device

// Port represents an open port on a device.
type Port = scanner.Port

// PortState represents the state of a port.
type PortState = scanner.PortState

// DiscoverLAN discovers devices on the local network.
func DiscoverLAN(ctx context.Context, opts ...scanner.DiscoveryOptions) ([]Device, error) {
    return scanner.DiscoverLAN(ctx, opts...)
}

// ProbeTCPPorts scans TCP ports on a single IP.
func ProbeTCPPorts(ctx context.Context, ip string, cfg scanner.TCPConfig) ([]Port, error) {
    return scanner.ProbeTCPPorts(ctx, ip, cfg)
}

// LookupVendor looks up MAC vendor by OUI prefix.
func LookupVendor(mac string) string {
    return util.LookupOUI(mac)
}

// GzipEncode compresses data.
func GzipEncode(data []byte) (string, error) {
    return util.GzipEncode(data)
}

// GzipDecode decompresses data.
func GzipDecode(encoded string) ([]byte, error) {
    return util.GzipDecode(encoded)
}
