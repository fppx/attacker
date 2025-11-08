package entity

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/fppx/attacker/internal/domain/scan/value"
)

// Scanner 扫描器接口
type Scanner interface {
	SetBPFFilter() error
	ProcessPacket(packet gopacket.Packet, seen map[string]struct{}, resultsCh chan<- value.IpMac)
	SendRequests(serializeOpts gopacket.SerializeOptions) error
	GetHandle() *pcap.Handle
}
