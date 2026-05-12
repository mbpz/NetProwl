package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// BannerConfig Banner 抓取配置
type BannerConfig struct {
	TimeoutMs        int
	IncludeDeepScan  bool // F2-4: HTTP deep scan with common paths
	IncludeRTSPSDP   bool // F2-5: RTSP DESCRIBE for stream info
}

// DefaultBannerConfig 默认配置
var DefaultBannerConfig = BannerConfig{
	TimeoutMs:       3000,
	IncludeDeepScan: true,
	IncludeRTSPSDP:  true,
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
		return grabHTTPBanner(ctx, ip, port, timeout, cfg.IncludeDeepScan)
	case 22:
		return grabSSHBanner(ctx, ip, port, timeout)
	case 21:
		return grabFTPBanner(ctx, ip, port, timeout)
	case 554, 5000:
		return grabRTSPBanner(ctx, ip, port, timeout, cfg.IncludeRTSPSDP)
	default:
		return grabGenericBanner(ctx, ip, port, timeout)
	}
}

// HTTPHeaders extracted from HTTP response
type HTTPHeaders struct {
	Server       string
	XPoweredBy   string
	XGenerator   string
	Title        string
	CMS          string
	PathsFound   []string
}

// parseHTTPHeaders parses HTTP response headers and body for F2-4
func parseHTTPHeaders(resp string) *HTTPHeaders {
	h := &HTTPHeaders{}
	lines := strings.Split(resp, "\r\n")

	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			h.Server = strings.TrimSpace(strings.TrimPrefix(line, "server:"))
		} else if strings.HasPrefix(lower, "x-powered-by:") {
			h.XPoweredBy = strings.TrimSpace(strings.TrimPrefix(line, "x-powered-by:"))
		} else if strings.HasPrefix(lower, "x-generator:") {
			h.XGenerator = strings.TrimSpace(strings.TrimPrefix(line, "x-generator:"))
		} else if strings.HasPrefix(lower, "<title>") || strings.HasPrefix(lower, "<title") {
			// HTML title extraction
			if idx := strings.Index(line, ">"); idx >= 0 {
				h.Title = strings.TrimSpace(line[idx+1:])
				if idx := strings.Index(h.Title, "<"); idx >= 0 {
					h.Title = h.Title[:idx]
				}
			}
		}
	}

	// Detect CMS
	h.CMS = detectCMS(h.Server, h.XPoweredBy, h.XGenerator, h.Title)

	return h
}

var cmsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)wordpress`),
	regexp.MustCompile(`(?i)phpmyadmin`),
	regexp.MustCompile(`(?i)drupal`),
	regexp.MustCompile(`(?i)joomla`),
	regexp.MustCompile(`(?i)nginx`),
	regexp.MustCompile(`(?i)apache`),
	regexp.MustCompile(`(?i)cowboy`),
	regexp.MustCompile(`(?i)tomcat`),
	regexp.MustCompile(`(?i)jetty`),
	regexp.MustCompile(`(?i)iis`),
	regexp.MustCompile(`(?i)express`),
	regexp.MustCompile(`(?i)django`),
	regexp.MustCompile(`(?i)laravel`),
	regexp.MustCompile(`(?i)codeigniter`),
}

func detectCMS(server, poweredBy, generator, title string) string {
	combined := strings.Join([]string{server, poweredBy, generator, title}, " ")
	for _, pat := range cmsPatterns {
		if pat.MatchString(combined) {
			matches := pat.FindStringSubmatch(combined)
			return strings.ToLower(matches[1])
		}
	}
	return ""
}

// grabHTTPBanner HTTP banner 抓取 + F2-4 HTTP deep probing
func grabHTTPBanner(ctx context.Context, ip string, port int, timeout time.Duration, deepScan bool) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprint(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	resp := strings.TrimSpace(string(buf[:n]))

	if deepScan && n > 0 {
		// Additional path probes for F2-4
		paths := []string{"/", "/admin", "/wp-login.php", "/phpmyadmin/", "/robots.txt", "/owa/"}
		found := []string{}
		for _, path := range paths {
			conn2, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout/3)
			if err != nil {
				continue
			}
			conn2.SetDeadline(time.Now().Add(timeout / 3))
			fmt.Fprint(conn2, fmt.Sprintf("GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", path))
			buf2 := make([]byte, 256)
			n2, _ := conn2.Read(buf2)
			resp2 := string(buf2[:n2])
			conn2.Close()
			if strings.Contains(resp2, "200") || strings.Contains(resp2, "401") || strings.Contains(resp2, "403") {
				found = append(found, path)
			}
		}
		if len(found) > 0 {
			resp += "\n[PATHS] " + strings.Join(found, ",")
		}
	}

	return resp, nil
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
	if err != nil && err != io.EOF {
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
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// RTSPStreamInfo F2-5 RTSP 流信息
type RTSPStreamInfo struct {
	Server     string
	StreamURL  string
	CameraBrand string
	Auth       string // "none", "basic", "digest"
}

// grabRTSPBanner RTSP banner + F2-5 流探测
func grabRTSPBanner(ctx context.Context, ip string, port int, timeout time.Duration, getSDP bool) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// OPTIONS request
	fmt.Fprint(conn, "OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 0\r\n\r\n")
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	resp := strings.TrimSpace(string(buf[:n]))

	if getSDP && n > 0 {
		// DESCRIBE for stream info (F2-5)
		conn.SetDeadline(time.Now().Add(timeout))
		fmt.Fprint(conn, "DESCRIBE rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n")
		buf2 := make([]byte, 1024)
		n2, err := conn.Read(buf2)
		if err == nil && n2 > 0 {
			sdp := strings.TrimSpace(string(buf2[:n2]))
			resp += "\n[SDP]" + parseRTSPSDP(sdp)
		}
	}

	return resp, nil
}

// parseRTSPSDP 解析 RTSP SDP 响应
func parseRTSPSDP(sdp string) string {
	var info RTSPStreamInfo
	lines := strings.Split(sdp, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "v=") {
			// version line, skip
		} else if strings.HasPrefix(lower, "o=") {
			// origin
		} else if strings.HasPrefix(lower, "s=") {
			// stream name
		} else if strings.HasPrefix(lower, "c=") {
			// connection info
		} else if strings.HasPrefix(lower, "a=control:") {
			info.StreamURL = strings.TrimSpace(strings.TrimPrefix(line, "a=control:"))
		}
	}

	// Detect camera brand from SDP
	lowerSdp := strings.ToLower(sdp)
	switch {
	case strings.Contains(lowerSdp, "hikvision"):
		info.CameraBrand = "Hikvision"
	case strings.Contains(lowerSdp, "dahua"):
		info.CameraBrand = "Dahua"
	case strings.Contains(lowerSdp, "uniview"):
		info.CameraBrand = "Uniview"
	case strings.Contains(lowerSdp, "ezviz") || strings.Contains(lowerSdp, "萤石"):
		info.CameraBrand = "Ezviz"
	case strings.Contains(lowerSdp, "rtsp"):
		info.CameraBrand = "Generic RTSP"
	}

	parts := []string{}
	if info.CameraBrand != "" {
		parts = append(parts, "brand:"+info.CameraBrand)
	}
	if info.StreamURL != "" {
		parts = append(parts, "url:"+info.StreamURL)
	}

	if len(parts) == 0 {
		return sdp
	}
	return strings.Join(parts, " ")
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
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}