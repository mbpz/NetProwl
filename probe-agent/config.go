package main

import (
	"os"
	"strconv"
)

type Config struct {
	ListenPort      int
	CloudWSURL      string // 云端中台 WebSocket 地址（可选）
	AuthToken       string // 配对 Token
	ScanConcurrency int    // 扫描并发数，默认 200
}

func DefaultConfig() *Config {
	return &Config{
		ListenPort:      9876,
		ScanConcurrency: 200,
	}
}

func LoadConfig() *Config {
	cfg := DefaultConfig()
	if port := os.Getenv("PROBE_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.ListenPort = p
		}
	}
	cfg.AuthToken = os.Getenv("PROBE_TOKEN")
	cfg.CloudWSURL = os.Getenv("CLOUD_WS_URL")
	return cfg
}