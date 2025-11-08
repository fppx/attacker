package entity

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/fppx/attacker/internal/domain/scan/value"
)

// IPv4Scanner IPv4 扫描实体
type IPv4Scanner struct {
	networkInterface *NetworkInterface
	handle           *pcap.Handle
	ipNet            *net.IPNet
}

// NewIPv4Scanner 创建 IPv4 扫描器
func NewIPv4Scanner(networkInterface *NetworkInterface, handle *pcap.Handle, ipNet *net.IPNet) *IPv4Scanner {
	return &IPv4Scanner{
		networkInterface: networkInterface,
		handle:           handle,
		ipNet:            ipNet,
	}
}

// SetBPFFilter 设置 BPF 过滤器
func (s *IPv4Scanner) SetBPFFilter() error {
	return s.handle.SetBPFFilter("arp and arp[6:2] = 2")
}

// ProcessPacket 处理数据包
func (s *IPv4Scanner) ProcessPacket(packet gopacket.Packet, seen map[string]struct{}, resultsCh chan<- value.IpMac) {
	if l := packet.Layer(layers.LayerTypeARP); l != nil {
		arp := l.(*layers.ARP)
		if arp.Operation == layers.ARPReply {
			ipStr := net.IP(arp.SourceProtAddress).String()
			macStr := net.HardwareAddr(arp.SourceHwAddress).String()
			if _, ok := seen[ipStr]; !ok {
				seen[ipStr] = struct{}{}
				resultsCh <- value.IpMac{
					IP:  ipStr,
					MAC: macStr,
				}
			}
		}
	}
}

// SendRequests 发送 ARP 请求
func (s *IPv4Scanner) SendRequests(serializeOpts gopacket.SerializeOptions) error {
	dstBroadcastMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	start, end := s.hostRange()

	for cur := start; cur <= end; cur++ {
		target := s.uint32ToIPv4(cur)
		if target.Equal(s.networkInterface.IP) {
			continue
		}

		if err := s.sendARPRequest(target, dstBroadcastMAC, serializeOpts); err != nil {
			return fmt.Errorf("发送 ARP 请求失败: %w", err)
		}
	}

	return nil
}

// sendARPRequest 发送单个 ARP 请求
func (s *IPv4Scanner) sendARPRequest(target net.IP, dstMAC net.HardwareAddr, serializeOpts gopacket.SerializeOptions) error {
	eth := layers.Ethernet{
		SrcMAC:       s.networkInterface.MAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.networkInterface.MAC),
		SourceProtAddress: []byte(s.networkInterface.IP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(target.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, &eth, &arp); err != nil {
		return err
	}

	return s.handle.WritePacketData(buf.Bytes())
}

// hostRange 计算主机地址范围
func (s *IPv4Scanner) hostRange() (uint32, uint32) {
	network := s.ipv4ToUint32(s.ipNet.IP)
	mask := s.ipv4ToUint32(net.IP(s.ipNet.Mask))
	broadcast := (network & mask) | (^mask)
	start := (network & mask) + 1
	end := broadcast - 1
	return start, end
}

// ipv4ToUint32 将 IPv4 地址转换为 uint32
func (s *IPv4Scanner) ipv4ToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	return (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])
}

// uint32ToIPv4 将 uint32 转换为 IPv4 地址
func (s *IPv4Scanner) uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// GetHandle 获取 pcap handle
func (s *IPv4Scanner) GetHandle() *pcap.Handle {
	return s.handle
}
