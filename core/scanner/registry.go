package scanner

import (
	"strings"

	"github.com/netprowl/core/types"
)

// ServiceRule 单条服务指纹规则
type ServiceRule struct {
	ID             string          `json:"id"`
	Port           int             `json:"port"`
	BannerContains string          `json:"bannerContains,omitempty"`
	Service        string          `json:"service"`
	DeviceType     types.DeviceType `json:"deviceType"`
}

// DefaultRegistry 默认服务指纹注册表
var DefaultRegistry = []ServiceRule{
	{ID: "http", Port: 80, BannerContains: "", Service: "HTTP", DeviceType: types.DeviceTypeUnknown},
	{ID: "https", Port: 443, BannerContains: "", Service: "HTTPS", DeviceType: types.DeviceTypeUnknown},
	{ID: "ssh", Port: 22, BannerContains: "SSH", Service: "SSH", DeviceType: types.DeviceTypeUnknown},
	{ID: "ftp", Port: 21, BannerContains: "FTP", Service: "FTP", DeviceType: types.DeviceTypeUnknown},
	{ID: "hikvision-camera", Port: 554, BannerContains: "Hikvision", Service: "Hikvision Camera", DeviceType: types.DeviceTypeCamera},
	{ID: "synology-nas", Port: 5000, BannerContains: "Synology", Service: "Synology NAS", DeviceType: types.DeviceTypeNAS},
	{ID: "rtsp", Port: 554, BannerContains: "RTSP", Service: "RTSP Stream", DeviceType: types.DeviceTypeCamera},
	{ID: "http-proxy", Port: 8080, BannerContains: "", Service: "HTTP Proxy", DeviceType: types.DeviceTypeUnknown},
	{ID: "upnp", Port: 1900, BannerContains: "UPnP", Service: "UPnP", DeviceType: types.DeviceTypeUnknown},
}

// Match 根据端口 + banner 匹配服务
func Match(port int, banner string) (service string, deviceType types.DeviceType) {
	for _, rule := range DefaultRegistry {
		if rule.Port != port {
			continue
		}
		if rule.BannerContains != "" && strings.Contains(banner, rule.BannerContains) {
			return rule.Service, types.DeviceTypeUnknown
		}
		if rule.BannerContains == "" {
			return rule.Service, types.DeviceTypeUnknown
		}
	}
	return "unknown", types.DeviceTypeUnknown
}