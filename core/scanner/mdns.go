package scanner

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/netprowl/core/types"
)

// MDNSConfig mDNS 扫描配置
type MDNSConfig struct {
	ServiceTypes []string
	Timeout      time.Duration
}

// DefaultMDNSConfig 默认配置
var DefaultMDNSConfig = MDNSConfig{
	ServiceTypes: []string{
		"_http._tcp",
		"_ftp._tcp",
		"_ssh._tcp",
		"_smb._tcp",
		"_airplay._tcp",
		"_googlecast._tcp",
		"_ipp._tcp",
	},
	Timeout: 5 * time.Second,
}

// DiscoverMDNS 发现 mDNS 服务
// 返回发现的设备列表
func DiscoverMDNS(ctx context.Context, cfg MDNSConfig) ([]types.Device, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	var devices []types.Device
	seen := make(map[string]bool)

	for _, serviceType := range cfg.ServiceTypes {
		select {
		case <-ctx.Done():
			return devices, ctx.Err()
		default:
		}

		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			continue
		}

		entries := make(chan *zeroconf.ServiceEntry)
		go func() {
			if err := resolver.Browse(context.Background(), serviceType, "local.", entries); err != nil {
				return
			}
		}()

		for entry := range entries {
			if entry == nil {
				break
			}

			for _, addr := range entry.AddrIPv4 {
				ip := addr.String()
				if seen[ip] {
					continue
				}
				seen[ip] = true

				device := types.Device{
					IP:         ip,
					Hostname:   entry.Instance,
					DeviceType: inferDeviceType(entry.Instance, serviceType),
					OS:         types.OSTypeUnknown,
				}
				devices = append(devices, device)
			}
		}
	}

	return devices, nil
}

// inferDeviceType 根据服务类型推断设备类型
func inferDeviceType(instanceName, serviceType string) types.DeviceType {
	name := strings.ToLower(instanceName)
	service := strings.ToLower(serviceType)

	switch {
	case strings.Contains(name, "camera") || strings.Contains(service, "rtsp"):
		return types.DeviceTypeCamera
	case strings.Contains(name, "nas") || strings.Contains(name, "synology") || strings.Contains(name, "qnap"):
		return types.DeviceTypeNAS
	case strings.Contains(name, "router") || strings.Contains(name, "gateway"):
		return types.DeviceTypeRouter
	case strings.Contains(name, "printer"):
		return types.DeviceTypePrinter
	case strings.Contains(name, "phone") || strings.Contains(name, "iphone") || strings.Contains(name, "android"):
		return types.DeviceTypePhone
	case strings.Contains(name, "macbook") || strings.Contains(name, "imac") || strings.Contains(name, "pc"):
		return types.DeviceTypePC
	default:
		return types.DeviceTypeUnknown
	}
}

// getLocalMAC 获取本机 MAC 地址（用于设备识别）
func getLocalMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 && i.HardwareAddr != nil {
			return i.HardwareAddr.String()
		}
	}
	return ""
}