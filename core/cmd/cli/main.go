package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/netprowl/core/scanner"
	"github.com/netprowl/core/types"
	"github.com/netprowl/core/util"
)

func main() {
	scanSubnet := flag.String("scan-subnet", "", "scan subnet e.g. 192.168.1.0/24")
	mdns := flag.Bool("mdns", false, "run mDNS discovery")
	ssdp := flag.Bool("ssdp", false, "run SSDP discovery")
	flag.Parse()

	ctx := context.Background()

	if *scanSubnet != "" {
		ips := util.ExpandSubnet(*scanSubnet)
		var allDevices []types.Device
		for _, ip := range ips {
			ports, err := scanner.ProbeTCPPorts(ctx, ip, scanner.TCPConfig{
				Ports:       []int{80, 443, 8080, 554, 5000, 9000},
				Concurrency: 50,
				TimeoutMs:   1000,
			})
			if err == nil && len(ports) > 0 {
				allDevices = append(allDevices, types.Device{
					IP:        ip,
					OpenPorts: ports,
				})
			}
		}
		json.NewEncoder(os.Stdout).Encode(allDevices)
		return
	}

	if *mdns {
		devs, err := scanner.DiscoverMDNS(ctx, scanner.MDNSConfig{
			Timeout: 5 * time.Second,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "mdns error: %v\n", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(devs)
		return
	}

	if *ssdp {
		devs, err := scanner.DiscoverSSDP(ctx, scanner.SSDPConfig{
			Timeout: 5 * time.Second,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssdp error: %v\n", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(devs)
		return
	}

	flag.Usage()
	os.Exit(1)
}