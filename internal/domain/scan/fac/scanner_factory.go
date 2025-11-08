package fac

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"

	"github.com/fppx/attacker/internal/domain/scan/entity"
)

// ScannerFactory 扫描器工厂
type ScannerFactory struct{}

// NewScannerFactory 创建扫描器工厂
func NewScannerFactory() *ScannerFactory {
	return &ScannerFactory{}
}

// CreateScanner 创建扫描器
func (f *ScannerFactory) CreateScanner(networkInterface *entity.NetworkInterface, handle *pcap.Handle, ipNet *net.IPNet) (entity.Scanner, error) {
	isIPv4 := ipNet.IP.To4() != nil
	if !isIPv4 && len(ipNet.IP) != 16 {
		return nil, fmt.Errorf("不支持的 IP 地址格式: %s", ipNet.IP.String())
	}

	if isIPv4 {
		return entity.NewIPv4Scanner(networkInterface, handle, ipNet), nil
	}
	return entity.NewIPv6Scanner(networkInterface, handle, ipNet), nil
}
