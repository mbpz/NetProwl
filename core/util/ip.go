package util

import (
	"net"
	"strings"
)

func InferSubnet(localIP string) string {
	parts := strings.Split(localIP, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

func ExpandSubnet(subnet string) []string {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IsPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsPrivate()
}

func InferOS(ttl int) string {
	switch {
	case ttl <= 64:
		return "linux"
	case ttl <= 128:
		return "windows"
	case ttl >= 255:
		return "network"
	default:
		return "unknown"
	}
}