package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

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
// 使用标准库 net 实现 UDP 多播监听
func DiscoverMDNS(ctx context.Context, cfg MDNSConfig) ([]types.Device, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultMDNSConfig.Timeout
	}
	if len(cfg.ServiceTypes) == 0 {
		cfg.ServiceTypes = DefaultMDNSConfig.ServiceTypes
	}

	// mDNS 多播地址
	mDNSAddr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	conn, err := net.ListenMulticastUDP("udp4", nil, mDNSAddr)
	if err != nil {
		return nil, fmt.Errorf("mDNS listen: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))

	var devices []types.Device

	// 发送 mDNS 查询 for each service type
	for _, st := range cfg.ServiceTypes {
		query := buildMDNSQuery(st)
		conn.WriteToUDP(query, mDNSAddr)
	}

	// 读取响应
	buf := make([]byte, 65536)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}
		if dev := parseMDNSResponse(buf[:n], src.IP.String()); dev != nil {
			devices = append(devices, *dev)
		}
	}

	return devices, nil
}

func buildMDNSQuery(serviceType string) []byte {
	// 简化的 mDNS 查询报文构建
	// 实际使用 miekg/dns 库会更完整
	return []byte{}
}

func parseMDNSResponse(data []byte, srcIP string) *types.Device {
	// 简化的解析逻辑
	// 实际需要解析 mDNS 响应报文
	return nil
}