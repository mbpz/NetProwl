package types

import "time"

type DeviceType string
type OSType string
type DiscoverySource string
type PortState string

const (
	DeviceTypeRouter  DeviceType = "router"
	DeviceTypePC      DeviceType = "pc"
	DeviceTypeCamera  DeviceType = "camera"
	DeviceTypeNAS    DeviceType = "nas"
	DeviceTypePhone   DeviceType = "phone"
	DeviceTypePrinter DeviceType = "printer"
	DeviceTypeUnknown DeviceType = "unknown"
)

const (
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"
	OSTypeNetwork OSType = "network"
	OSTypeUnknown OSType = "unknown"
)

const (
	DiscoverySourceMDNS DiscoverySource = "mdns"
	DiscoverySourceSSDP DiscoverySource = "ssdp"
	DiscoverySourceTCP  DiscoverySource = "tcp"
)

const (
	PortStateOpen     PortState = "open"
	PortStateFiltered PortState = "filtered"
	PortStateClosed   PortState = "closed"
)

type Port struct {
	Port    int       `json:"port"`
	Service string    `json:"service,omitempty"`
	State   PortState `json:"state"`
	Banner  string    `json:"banner,omitempty"`
}

type Device struct {
	ID           string           `json:"id"`
	IP           string           `json:"ip"`
	MAC          string           `json:"mac,omitempty"`
	Hostname     string           `json:"hostname,omitempty"`
	Vendor       string           `json:"vendor,omitempty"`
	DeviceType   DeviceType      `json:"deviceType"`
	OS           OSType          `json:"os"`
	OpenPorts    []Port          `json:"openPorts"`
	DiscoveredAt time.Time       `json:"discoveredAt"`
	Sources      []DiscoverySource `json:"sources"`
	TTL          int             `json:"ttl,omitempty"`
}

type ScanResult struct {
	Devices         []Device `json:"devices"`
	DurationMs     int64    `json:"durationMs"`
	MDNSUnavailable bool     `json:"mdnsUnavailable"`
}