package entity

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/fppx/attacker/internal/domain/scan/value"
)

// IPv6Scanner IPv6 扫描实体
type IPv6Scanner struct {
	networkInterface *NetworkInterface
	handle           *pcap.Handle
	ipNet            *net.IPNet
}

// NewIPv6Scanner 创建 IPv6 扫描器
func NewIPv6Scanner(networkInterface *NetworkInterface, handle *pcap.Handle, ipNet *net.IPNet) *IPv6Scanner {
	return &IPv6Scanner{
		networkInterface: networkInterface,
		handle:           handle,
		ipNet:            ipNet,
	}
}

// SetBPFFilter 设置 BPF 过滤器
func (s *IPv6Scanner) SetBPFFilter() error {
	return s.handle.SetBPFFilter("icmp6 and ip6[40] = 136")
}

// ProcessPacket 处理数据包
func (s *IPv6Scanner) ProcessPacket(packet gopacket.Packet, seen map[string]struct{}, resultsCh chan<- value.IpMac) {
	if ndLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); ndLayer != nil {
		nd := ndLayer.(*layers.ICMPv6NeighborAdvertisement)
		ipStr := nd.TargetAddress.String()

		var macStr string
		for _, opt := range nd.Options {
			if opt.Type == layers.ICMPv6OptTargetAddress && len(opt.Data) >= 6 {
				macStr = net.HardwareAddr(opt.Data[:6]).String()
				break
			}
		}

		if macStr != "" {
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

// SendRequests 发送 Neighbor Solicitation 请求
func (s *IPv6Scanner) SendRequests(serializeOpts gopacket.SerializeOptions) error {
	targets := s.hostRange()

	for _, target := range targets {
		if target.Equal(s.networkInterface.IP) {
			continue
		}

		if err := s.sendNeighborSolicitation(target, serializeOpts); err != nil {
			return fmt.Errorf("发送 Neighbor Solicitation 失败: %w", err)
		}
	}

	return nil
}

// sendNeighborSolicitation 发送单个 Neighbor Solicitation
func (s *IPv6Scanner) sendNeighborSolicitation(target net.IP, serializeOpts gopacket.SerializeOptions) error {
	multicastIP := s.calculateSolicitedNodeMulticast(target)
	ipv6MulticastMAC := s.calculateIPv6MulticastMAC(multicastIP)

	eth := layers.Ethernet{
		SrcMAC:       s.networkInterface.MAC,
		DstMAC:       ipv6MulticastMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      s.networkInterface.IP,
		DstIP:      multicastIP,
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	nd := layers.ICMPv6NeighborSolicitation{
		TargetAddress: target,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: s.networkInterface.MAC,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, &eth, &ipv6, &icmpv6, &nd); err != nil {
		return err
	}

	return s.handle.WritePacketData(buf.Bytes())
}

// hostRange 计算主机地址范围
func (s *IPv6Scanner) hostRange() []net.IP {
	network := s.ipNet.IP
	mask := s.ipNet.Mask

	ones, _ := mask.Size()
	targets := make([]net.IP, 0)
	//最多12万的ip探测，一般局域网不会多余该数
	for i := 1; i < (1<<(128-ones)) && i <= 128000; i++ {
		target := make(net.IP, 16)
		copy(target, network)

		hostPart := uint64(i)
		//uint64无法与[]byte直接位运算，所以一个一个字节进行运算
		for j := 15; j >= 0 && hostPart > 0; j-- {
			target[j] = byte(hostPart & 0xff)
			hostPart >>= 8
		}

		//hostPort第一次运算时，会固定替换8个字节的位置，所以这里要恢复
		for j := 0; j < 16; j++ {
			target[j] = (target[j] & ^mask[j]) | (network[j] & mask[j])
		}
		targets = append(targets, target)
	}

	return targets
}

// calculateSolicitedNodeMulticast 计算 IPv6 solicited-node multicast 地址
func (s *IPv6Scanner) calculateSolicitedNodeMulticast(target net.IP) net.IP {
	multicast := make(net.IP, 16)
	multicast[0] = 0xff
	multicast[1] = 0x02
	multicast[11] = 0x01
	multicast[12] = 0xff
	if len(target) >= 16 {
		copy(multicast[13:], target[13:16])
	}
	return multicast
}

// calculateIPv6MulticastMAC 计算 IPv6 多播 MAC 地址
func (s *IPv6Scanner) calculateIPv6MulticastMAC(ipv6 net.IP) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	mac[0] = 0x33
	mac[1] = 0x33
	if len(ipv6) >= 16 {
		copy(mac[2:], ipv6[12:16])
	}
	return mac
}

// GetHandle 获取 pcap handle
func (s *IPv6Scanner) GetHandle() *pcap.Handle {
	return s.handle
}
