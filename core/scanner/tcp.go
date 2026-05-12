package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netprowl/core/types"
)

// WHITE_PORTS 白名单端口（微信小程序允许）
var WHITE_PORTS = []int{80, 443, 8080, 8443, 554, 5000, 9000, 49152}

// TCPConfig TCP 扫描配置
type TCPConfig struct {
	Ports       []int // 目标端口，为空则使用 WHITE_PORTS
	Concurrency int   // 并发连接数，默认 100
	TimeoutMs   int   // 单端口超时(ms)，默认 2000
}

// DefaultTCPConfig 默认配置（白名单端口）
var DefaultTCPConfig = TCPConfig{
	Ports:       WHITE_PORTS,
	Concurrency: 100,
	TimeoutMs:   2000,
}

const (
	defaultTimeout = 2 * time.Second
	maxConcurrency = 200
)

// PortProbe is the scanning result for a single port probe.
// Renamed from ScanResult to avoid confusion with types.ScanResult.
type PortProbe struct {
	IP    string
	Port  int
	State string // "open" | "closed"
	Banner string
}

// ProbeTCPPorts 扫描单个 IP 的端口
func ProbeTCPPorts(ctx context.Context, ip string, cfg TCPConfig) ([]types.Port, error) {
	if len(cfg.Ports) == 0 {
		cfg.Ports = WHITE_PORTS
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = defaultTimeout
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 100
	}

	results := make([]PortProbe, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, port := range cfg.Ports {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := probePort(ip, port, timeout)
			mu.Lock()
			if result.State == "open" {
				results = append(results, result)
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	return buildPortList(results), nil
}

// ProbeTCPPort 探测单个端口
func ProbeTCPPort(ctx context.Context, ip string, port int, timeout time.Duration) (types.Port, error) {
	result := probePort(ip, port, timeout)
	if result.State != "open" {
		return types.Port{Port: port, State: types.PortStateClosed}, nil
	}
	return types.Port{
		Port:    port,
		State:   types.PortStateOpen,
		Service: GuessService(port),
		Banner:  result.Banner,
	}, nil
}

func probePort(ip string, port int, timeout time.Duration) PortProbe {
	result := PortProbe{IP: ip, Port: port, State: "closed"}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return result
	}
	defer conn.Close()
	result.State = "open"
	result.Banner = grabBanner(conn, port)
	return result
}

func grabBanner(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	switch port {
	case 80, 8080, 8443:
		fmt.Fprint(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

func buildPortList(results []PortProbe) []types.Port {
	ports := make([]types.Port, 0, len(results))
	for _, r := range results {
		ports = append(ports, types.Port{
			Port:    r.Port,
			State:   types.PortState(r.State),
			Service: GuessService(r.Port),
			Banner:  r.Banner,
		})
	}
	return ports
}

var serviceMap = map[int]string{
	80:   "http",
	443:  "https",
	22:   "ssh",
	21:   "ftp",
	25:   "smtp",
	110:  "pop3",
	143:  "imap",
	135:  "msrpc",
	139:  "netbios",
	445:  "smb",
	3389: "rdp",
	8080: "http-alt",
	8443: "https-alt",
	5000: "upnp",
	9000: "cslistener",
	554:  "rtsp",
}

func GuessService(port int) string {
	if s, ok := serviceMap[port]; ok {
		return s
	}
	return "unknown"
}
