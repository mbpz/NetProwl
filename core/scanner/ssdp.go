package scanner

import (
	"context"
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
	// Stub: 暂不实现真实 SSDP 扫描
	// 后续通过 UDP socket 实现
	return nil, nil
}

// parseSSDPResponse 解析 SSDP 响应
func parseSSDPResponse(banner string, ip string) *types.Device {
	// TODO: 实现解析逻辑
	return nil
}