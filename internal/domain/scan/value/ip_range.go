package value

import "net"

// IPRange 表示 IP 地址范围值对象
type IPRange struct {
	Start net.IP
	End   net.IP
}

// IPv4Range 表示 IPv4 地址范围
type IPv4Range struct {
	Start uint32
	End   uint32
}

// IPv6Range 表示 IPv6 地址范围（地址列表）
type IPv6Range struct {
	Addresses []net.IP
}
