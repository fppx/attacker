package value

// NetworkSegment 表示网络段值对象
type NetworkSegment struct {
	CIDR      string
	Interface string
	IP        string
	MAC       string
	IsIPv4    bool
}
