package scanner

import (
	"context"
	"net"
	"time"

	"github.com/netprowl/core/types"
)

const (
	SSDP_ADDR = "239.255.255.250"
	SSDP_PORT = 1900
	M_SEARCH  = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
)

// SSDPConfig SSDP 扫描配置
type SSDPConfig struct {
	Timeout time.Duration
}

// DefaultSSDPConfig 默认配置
var DefaultSSDPConfig = SSDPConfig{
	Timeout: 5 * time.Second,
}

// DiscoverSSDP 发现 SSDP/UPnP 设备
func DiscoverSSDP(ctx context.Context, cfg SSDPConfig) ([]types.Device, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultSSDPConfig.Timeout
	}

	// 创建 UDP 连接
	addr := &net.UDPAddr{IP: net.ParseIP(SSDP_ADDR), Port: SSDP_PORT}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))

	// 发送 M-SEARCH
	_, err = conn.WriteToUDP([]byte(M_SEARCH), addr)
	if err != nil {
		return nil, err
	}

	var devices []types.Device
	buf := make([]byte, 4096)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}
		if dev := parseSSDPResponse(string(buf[:n]), src.IP.String()); dev != nil {
			dev.Sources = []types.DiscoverySource{types.DiscoverySourceSSDP}
			devices = append(devices, *dev)
		}
	}

	return devices, nil
}

// parseSSDPResponse 解析 SSDP 响应
func parseSSDPResponse(banner string, ip string) *types.Device {
	// 解析 HTTP-style SSDP 通知
	// Location: http://192.168.1.1:1900.xml
	// SERVER: Linux/2.6 UPnP/1.0 Product/1.0
	device := &types.Device{
		IP:        ip,
		Hostname:  "",
		OpenPorts: []types.Port{},
	}

	// 简单按行解析
	for _, line := range splitLines(banner) {
		if contains(line, "LOCATION:") {
			// 提取 URL
		}
		if contains(line, "SERVER:") || contains(line, "Server:") {
			// 提取设备信息
			device.Hostname = trimServer(line)
		}
		if contains(line, "ST:") {
			// 提取服务类型
		}
	}

	return device
}

func splitLines(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			if start < i {
				result = append(result, s[start:i])
			}
			start = i + 1
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr) >= 0))
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimServer(line string) string {
	// 移除 "SERVER:" 或 "Server:" 前缀
	idx := findSubstring(line, ":")
	if idx >= 0 && idx+1 < len(line) {
		rest := line[idx+1:]
		// 跳过空格
		for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			rest = rest[1:]
		}
		return rest
	}
	return line
}