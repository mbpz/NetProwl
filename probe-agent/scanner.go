package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	IP     string
	Port   int
	State  string // "open", "closed", "filtered"
	Banner string
}

func (a *Agent) ScanHost(ip string, ports []int) ([]ScanResult, error) {
	var wg sync.WaitGroup
	results := make([]ScanResult, 0, len(ports))
	var mu sync.Mutex

	sem := make(chan struct{}, a.config.ScanConcurrency)

	for _, port := range ports {
		sem <- struct{}{} // acquire BEFORE wg.Add to avoid deadlock if panic occurs before wg.Done
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := a.probePort(ip, port)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return results, nil
}

func (a *Agent) probePort(ip string, port int) ScanResult {
	result := ScanResult{
		IP:    ip,
		Port:  port,
		State: "closed",
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.State = "open"
	result.Banner = a.grabBanner(conn, port)
	return result
}

func (a *Agent) grabBanner(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(1 * time.Second))

	switch port {
	case 80, 8080, 8443:
		fmt.Fprint(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && n > 0 {
		return strings.TrimSpace(string(buf[:n]))
	}
	return ""
}