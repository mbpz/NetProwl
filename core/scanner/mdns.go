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
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0)     // Transaction ID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Flags: standard query
	binary.BigEndian.PutUint16(buf[4:6], 1)       // Questions: 1
	binary.BigEndian.PutUint16(buf[6:8], 0)      // Answers: 0
	binary.BigEndian.PutUint16(buf[8:10], 0)     // Authority: 0
	binary.BigEndian.PutUint16(buf[10:12], 0)    // Additional: 0

	// Add question in DNS format
	for _, part := range strings.Split(serviceType, ".") {
		if len(part) > 63 {
			part = part[:63]
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, part...)
	}
	buf = append(buf, 0) // null terminator

	// QTYPE: PTR (12)
	buf = append(buf, 0, 12)
	// QCLASS: IN (1), with QU flag (0x8000)
	buf = append(buf, 0x80, 0x01)

	return buf
}

func parseMDNSResponse(data []byte, srcIP string) *types.Device {
	if len(data) < 12 {
		return nil
	}

	// Skip header
	offset := 12

	// Skip questions
	for offset < len(data) {
		if data[offset] == 0 {
			offset += 5 // null + QTYPE + QCLASS
			break
		}
		offset += 1 + int(data[offset])
	}

	var ip, hostname string
	var port int

	// Parse resource records
	for offset < len(data) {
		if offset+12 > len(data) {
			break
		}

		// Skip name
		consumed := skipDNSName(data, offset)
		offset += consumed

		if offset+10 > len(data) {
			break
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		// CLASS
		offset += 2
		// TTL
		offset += 4
		rdlength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+rdlength > len(data) {
			break
		}

		rdata := data[offset : offset+rdlength]
		offset += rdlength

		switch qtype {
		case 1: // A record - IPv4
			if rdlength == 4 {
				ip = fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
			}
		case 33: // SRV record
			if rdlength >= 6 {
				port = int(binary.BigEndian.Uint16(rdata[4:6]))
				hostname = readDNSName(rdata, 6)
			}
		}
	}

	if ip == "" {
		return nil
	}

	return &types.Device{
		IP:        ip,
		Hostname:  hostname,
		OpenPorts: []types.Port{},
	}
}

func skipDNSName(data []byte, offset int) int {
	// Simplified: skip compressed/uncompressed name
	// Returns bytes consumed
	if data[offset]&0xC0 == 0xC0 {
		return 2 // pointer
	}
	start := offset
	for offset < len(data) && data[offset] != 0 {
		offset += 1 + int(data[offset])
	}
	return offset - start + 1
}

func readDNSName(data []byte, offset int) string {
	// Read DNS name starting at offset (after length bytes)
	var parts []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			break
		}
		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}
	return strings.Join(parts, ".")
}