package service

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/fppx/attacker/internal/domain/scan/entity"
	"github.com/fppx/attacker/internal/domain/scan/fac"
	"github.com/fppx/attacker/internal/domain/scan/value"
)

// scanService 扫描服务实现
type scanService struct {
	scannerFactory *fac.ScannerFactory
}

// NewScanService 创建扫描服务
func NewScanService() ScanService {
	return &scanService{
		scannerFactory: fac.NewScannerFactory(),
	}
}

// Scan 执行扫描
func (s *scanService) Scan(cidr string) ([]value.IpMac, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDR 解析失败: %w", err)
	}

	// 判断是 IPv4 还是 IPv6
	isIPv4 := ip.To4() != nil
	if !isIPv4 && len(ip) != 16 {
		return nil, fmt.Errorf("不支持的 IP 地址格式: %s", ip.String())
	}

	// 查找匹配的网络接口
	networkInterface, err := entity.FindUsableInterface(ipNet)
	if err != nil {
		return nil, fmt.Errorf("选择网卡失败: %w", err)
	}

	// 打开 pcap handle
	handle, err := pcap.OpenLive(networkInterface.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("打开设备失败: %w", err)
	}
	defer handle.Close()

	// 创建扫描器
	scanner, err := s.scannerFactory.CreateScanner(networkInterface, handle, ipNet)
	if err != nil {
		return nil, err
	}

	// 设置 BPF 过滤器
	if err := scanner.SetBPFFilter(); err != nil {
		return nil, fmt.Errorf("设置 BPF 过滤器失败: %w", err)
	}

	// 启动数据包捕获
	resultsCh := make(chan value.IpMac, 1024)
	seen := make(map[string]struct{})
	stopRead := make(chan struct{})

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go s.capturePackets(packetSource, scanner, seen, resultsCh, stopRead)

	// 发送请求
	serializeOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := scanner.SendRequests(serializeOpts); err != nil {
		return nil, err
	}

	// 等待回复收集完成
	go func() {
		time.Sleep(3 * time.Second)
		close(stopRead)
		time.Sleep(1 * time.Second)
		close(resultsCh)
	}()

	// 收集结果
	results := make([]value.IpMac, 0)
	for r := range resultsCh {
		results = append(results, value.IpMac{
			IP:     strings.ToUpper(r.IP),
			MAC:    strings.ToUpper(r.MAC),
			ReqIp:  strings.ToUpper(r.ReqIp),
			ReqMac: strings.ToUpper(r.ReqMac),
		})
	}

	return results, nil
}

// capturePackets 捕获数据包
func (s *scanService) capturePackets(
	packetSource *gopacket.PacketSource,
	scanner entity.Scanner,
	seen map[string]struct{},
	resultsCh chan<- value.IpMac,
	stopRead chan struct{},
) {
	for packet := range packetSource.Packets() {
		select {
		case <-stopRead:
			return
		default:
		}

		scanner.ProcessPacket(packet, seen, resultsCh)
	}
}
