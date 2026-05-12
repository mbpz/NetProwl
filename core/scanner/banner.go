package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// BannerConfig Banner 抓取配置
type BannerConfig struct {
	TimeoutMs int
}

// DefaultBannerConfig 默认配置
var DefaultBannerConfig = BannerConfig{
	TimeoutMs: 3000,
}

// GrabBanner 抓取服务 banner
// 支持 HTTP、SSH、FTP、SMTP、RTSP 等协议的 banner 提取
func GrabBanner(ctx context.Context, ip string, port int, cfg BannerConfig) (string, error) {
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 3000
	}
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

	switch port {
	case 80, 8080, 8443:
		return grabHTTPBanner(ctx, ip, port, timeout)
	case 22:
		return grabSSHBanner(ctx, ip, port, timeout)
	case 21:
		return grabFTPBanner(ctx, ip, port, timeout)
	case 554, 5000:
		return grabRTSPBanner(ctx, ip, port, timeout)
	default:
		return grabGenericBanner(ctx, ip, port, timeout)
	}
}

// grabHTTPBanner HTTP banner 抓取
func grabHTTPBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprint(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// grabSSHBanner SSH banner 抓取
func grabSSHBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// grabFTPBanner FTP banner 抓取
func grabFTPBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// grabRTSPBanner RTSP banner 抓取
func grabRTSPBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	// Send RTSP OPTIONS request
	fmt.Fprint(conn, "OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n")

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// grabGenericBanner 通用 banner 抓取
func grabGenericBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}