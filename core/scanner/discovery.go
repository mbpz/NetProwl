package scanner

import (
    "context"
    "net"
    "time"

    "github.com/netprowl/core/types"
    "github.com/netprowl/core/util"
)

// DiscoveryOptions 扫描选项
type DiscoveryOptions struct {
    Concurrency int
    Timeout     time.Duration
    IncludeMDNS bool
    IncludeSSDP bool
}

// DefaultDiscoveryOptions 默认选项
var DefaultDiscoveryOptions = DiscoveryOptions{
    Concurrency: 50,
    Timeout:     10 * time.Second,
    IncludeMDNS: true,
    IncludeSSDP: true,
}

// DiscoverLAN 发现局域网内所有设备
func DiscoverLAN(ctx context.Context, opts ...DiscoveryOptions) ([]types.Device, error) {
    opt := DefaultDiscoveryOptions
    if len(opts) > 0 {
        opt = opts[0]
    }

    var allDevices []types.Device
    seen := make(map[string]bool)

    // 1. mDNS discovery
    if opt.IncludeMDNS {
        mdnsDevices, err := DiscoverMDNS(ctx, MDNSConfig{
            ServiceTypes: []string{
                "_http._tcp",
                "_ftp._tcp",
                "_ssh._tcp",
                "_smb._tcp",
                "_airplay._tcp",
                "_googlecast._tcp",
                "_ipp._tcp",
            },
            Timeout: opt.Timeout,
        })
        if err == nil && len(mdnsDevices) > 0 {
            for _, d := range mdnsDevices {
                if !seen[d.IP] {
                    allDevices = append(allDevices, d)
                    seen[d.IP] = true
                }
            }
        }
    }

    // 2. SSDP discovery
    if opt.IncludeSSDP {
        ssdpDevices, err := DiscoverSSDP(ctx, SSDPConfig{
            Timeout: opt.Timeout,
        })
        if err == nil && len(ssdpDevices) > 0 {
            for _, d := range ssdpDevices {
                if !seen[d.IP] {
                    allDevices = append(allDevices, d)
                    seen[d.IP] = true
                }
            }
        }
    }

    // 3. TCP port scan on local subnet
    localIP := getLocalIP()
    if localIP != "" {
        subnet := util.InferSubnet(localIP)
        ips := util.ExpandSubnet(subnet)
        for _, ip := range ips {
            if seen[ip] {
                continue
            }
            // Quick scan common ports using ProbeTCPPorts
            results, err := ProbeTCPPorts(ctx, ip, TCPConfig{
                Ports:       []int{80, 443, 8080, 554, 5000, 9000},
                Concurrency: 50,
                TimeoutMs:   1000,
            })
            if err == nil && len(results) > 0 && !seen[ip] {
                device := types.Device{
                    IP:        ip,
                    DeviceType: types.DeviceTypeUnknown,
                    OS:        types.OSTypeUnknown,
                    OpenPorts: results,
                }
                allDevices = append(allDevices, device)
                seen[ip] = true
            }
        }
    }

    return allDevices, nil
}

// getLocalIP 获取本机 IP（简化版）
func getLocalIP() string {
    interfaces, _ := net.InterfaceAddrs()
    for _, addr := range interfaces {
        if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
            if ip.IP.To4() != nil {
                return ip.IP.String()
            }
        }
    }
    return ""
}
