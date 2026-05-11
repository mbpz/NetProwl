package main

import "log"

func main() {
	cfg := LoadConfig()
	agent := NewAgent(cfg)
	if err := agent.Start(); err != nil {
		log.Fatalf("Agent failed to start: %v", err)
	}
}