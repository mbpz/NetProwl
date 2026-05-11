package main

import (
	"os"
)

type Config struct {
	ListenPort  int
	DeepSeekKey string
	DeepSeekURL string
}

func LoadCloudConfig() *Config {
	return &Config{
		ListenPort:  8080,
		DeepSeekKey: os.Getenv("DEEPSEEK_API_KEY"),
		DeepSeekURL: getEnv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}