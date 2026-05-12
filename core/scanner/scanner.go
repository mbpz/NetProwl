package scanner

import (
	"context"
	"github.com/netprowl/core/types"
)

// Config 扫描配置
type Config struct {
	Subnet         string // 目标子网，如 "192.168.1.0/24"
	TargetIPs      []string // 目标 IP 列表（优先于 Subnet）
	Concurrency    int      // 并发数，默认 100
	TimeoutMs      int      // 单端口超时，默认 2000ms
	WhitePortsOnly bool     // 仅使用白名单端口（小程序用）
}

// Scanner 扫描器接口
type Scanner interface {
	Run(ctx context.Context, cfg Config) (*types.ScanResult, error)
}

// Registry 服务指纹注册表接口
type Registry interface {
	Match(port int, banner string) (service string, deviceType types.DeviceType)
}

// NewScanner 创建默认扫描器
func NewScanner() Scanner {
	return &defaultScanner{}
}

type defaultScanner struct{}

func (s *defaultScanner) Run(ctx context.Context, cfg Config) (*types.ScanResult, error) {
	return &types.ScanResult{
		Devices:    []types.Device{},
		DurationMs: 0,
	}, nil
}