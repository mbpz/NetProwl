package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/netprowl/core/types"
	"github.com/netprowl/core/util"
)

// compositeScanner 组合扫描器，协调所有发现方法
type compositeScanner struct{}

// NewScanner 创建组合扫描器
func NewScanner() Scanner {
	return &compositeScanner{}
}

func (s *compositeScanner) Run(ctx context.Context, cfg Config) (*types.ScanResult, error) {
	start := time.Now()

	// Determine target IPs
	var targetIPs []string
	if len(cfg.TargetIPs) > 0 {
		targetIPs = cfg.TargetIPs
	} else if cfg.Subnet != "" {
		targetIPs = util.ExpandSubnet(cfg.Subnet)
	}

	// If no subnet/IPs provided, infer from local IP or use common gateway scan
	if len(targetIPs) == 0 {
		targetIPs = inferLocalSubnet()
	}

	// Phase 1: mDNS discovery
	mdnsDevices, _ := DiscoverMDNS(ctx, MDNSConfig{Timeout: 5 * time.Second})

	// Phase 2: SSDP discovery
	ssdpDevices, _ := DiscoverSSDP(ctx, SSDPConfig{Timeout: 5 * time.Second})

	// Merge mDNS + SSDP devices into a map keyed by IP
	deviceMap := make(map[string]*types.Device)
	for i := range mdnsDevices {
		d := &mdnsDevices[i]
		d.DiscoveredAt = time.Now()
		if d.Sources == nil {
			d.Sources = []types.DiscoverySource{types.DiscoverySourceMDNS}
		}
		deviceMap[d.IP] = d
	}
	for i := range ssdpDevices {
		d := &ssdpDevices[i]
		if existing, ok := deviceMap[d.IP]; ok {
			existing.Sources = append(existing.Sources, types.DiscoverySourceSSDP)
		} else {
			d.DiscoveredAt = time.Now()
			if d.Sources == nil {
				d.Sources = []types.DiscoverySource{types.DiscoverySourceSSDP}
			}
			deviceMap[d.IP] = d
		}
	}

	// Phase 3: TCP port scan on gateway + discovered IPs
	// Always include likely gateway IPs (last 3 IPs of /24 subnet)
	gatewayCandidates := getGatewayCandidates(targetIPs)
	for _, ip := range gatewayCandidates {
		if _, exists := deviceMap[ip]; !exists {
			deviceMap[ip] = &types.Device{
				IP:          ip,
				Hostname:    "",
				OpenPorts:   []types.Port{},
				Sources:     []types.DiscoverySource{},
				DiscoveredAt: time.Now(),
			}
		}
	}

	// TCP scan each device
	tcpConfig := TCPConfig{
		Ports:       WHITE_PORTS,
		Concurrency: 100,
		TimeoutMs:   2000,
	}
	if cfg.WhitePortsOnly {
		tcpConfig.Ports = WHITE_PORTS
	}

	// Determine scan targets: all IPs in deviceMap + gateway candidates
	scanTargets := make(map[string]bool)
	for ip := range deviceMap {
		scanTargets[ip] = true
	}
	for _, ip := range gatewayCandidates {
		scanTargets[ip] = true
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for ip := range scanTargets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ports, _ := ProbeTCPPorts(ctx, ip, tcpConfig)
			if len(ports) > 0 {
				// Grab banner for first open port
				for _, p := range ports {
					if p.State == types.PortStateOpen {
						banner, _ := GrabBanner(ctx, ip, p.Port, DefaultBannerConfig)
						p.Banner = banner
						// Match service
						service, devType := Match(p.Port, banner)
						p.Service = service

						mu.Lock()
						if dev, ok := deviceMap[ip]; ok {
							dev.OpenPorts = append(dev.OpenPorts, p)
							// Infer device type from service
							if dev.DeviceType == types.DeviceTypeUnknown && devType != types.DeviceTypeUnknown {
								dev.DeviceType = devType
							}
						}
						mu.Unlock()
						break // only banner grab first open port
					}
				}
			}
		}(ip)
	}
	wg.Wait()

	// Build result
	devices := make([]types.Device, 0, len(deviceMap))
	for _, d := range deviceMap {
		// Only include devices with open ports or meaningful discovery source
		if len(d.OpenPorts) > 0 || len(d.Sources) > 0 {
			// Infer OS from TTL if available
			if d.OS == types.OSTypeUnknown && d.TTL > 0 {
				osStr := util.InferOS(d.TTL)
				switch osStr {
				case "linux":
					d.OS = types.OSTypeLinux
				case "windows":
					d.OS = types.OSTypeWindows
				case "network":
					d.OS = types.OSTypeNetwork
				default:
					d.OS = types.OSTypeUnknown
				}
			}
			// Vendor from MAC if available
			if d.MAC != "" && d.Vendor == "" {
				d.Vendor = util.LookupVendor(d.MAC)
			}
			devices = append(devices, *d)
		}
	}

	// Check if mDNS returned zero devices (indicates platform limitation)
	mdnsUnavailable := len(mdnsDevices) == 0

	return &types.ScanResult{
		Devices:         devices,
		DurationMs:      time.Since(start).Milliseconds(),
		MDNSUnavailable: mdnsUnavailable,
	}, nil
}

// getGatewayCandidates returns likely gateway IPs in a subnet
func getGatewayCandidates(targetIPs []string) []string {
	seen := make(map[string]bool)
	candidates := []string{}
	// Common gateway patterns: .1, .254, last IP in /24
	for _, ip := range targetIPs {
		p := strings.Split(ip, ".")
		if len(p) != 4 {
			continue
		}
		third := p[2]
		for _, last := range []string{"1", "254", "255"} {
			candidate := third + "." + last
			if !seen[candidate] {
				seen[candidate] = true
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

// inferLocalSubnet tries to get local IP and infer /24 subnet
func inferLocalSubnet() []string {
	// Get all local IPs and build /24 ranges
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return util.ExpandSubnet(util.InferSubnet(ipnet.IP.String()))
		}
	}
	// Fallback
	return util.ExpandSubnet("192.168.1.0/24")
}