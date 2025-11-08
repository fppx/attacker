package entity

import (
	"errors"
	"fmt"
	"net"

	"github.com/fppx/attacker/internal/domain/scan/value"
)

// NetworkInterface 表示网络接口实体
type NetworkInterface struct {
	Interface *net.Interface
	IP        net.IP
	MAC       net.HardwareAddr
}

// FindUsableInterface 查找匹配目标网段的网络接口
func FindUsableInterface(ipNet *net.IPNet) (*NetworkInterface, error) {
	isIPv4 := ipNet.IP.To4() != nil
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for i := range ifaces {
		iface := &ifaces[i]
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("获取网卡地址失败: %w", err)
		}

		for _, ifaceAddr := range ifaceAddrs {
			switch ifaceAddrV := ifaceAddr.(type) {
			case *net.IPNet:
				// 检查 IP 版本是否匹配
				ifaceIsIPv4 := ifaceAddrV.IP.To4() != nil
				if isIPv4 != ifaceIsIPv4 {
					continue
				}

				if ipNet.Contains(ifaceAddrV.IP) {
					if len(iface.HardwareAddr) == 0 {
						continue
					}
					return &NetworkInterface{
						Interface: iface,
						IP:        ifaceAddrV.IP,
						MAC:       iface.HardwareAddr,
					}, nil
				}
			}
		}
	}

	return nil, errors.New("未找到匹配网段的活动网卡")
}

// GetAllAvailableSegments 获取所有可用的网络段
func GetAllAvailableSegments() ([]*value.NetworkSegment, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %w", err)
	}

	segments := make([]*value.NetworkSegment, 0)

	for i := range ifaces {
		iface := &ifaces[i]
		// 跳过未启动或回环接口
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, ifaceAddr := range ifaceAddrs {
			switch ifaceAddrV := ifaceAddr.(type) {
			case *net.IPNet:
				// 跳过没有硬件地址的接口（IPv6 可能没有）
				if len(iface.HardwareAddr) == 0 {
					continue
				}

				// 计算 CIDR
				ones, bits := ifaceAddrV.Mask.Size()
				if ones == 0 && bits == 0 {
					continue
				}

				cidr := fmt.Sprintf("%s/%d", ifaceAddrV.IP.String(), ones)
				isIPv4 := ifaceAddrV.IP.To4() != nil

				segments = append(segments, &value.NetworkSegment{
					CIDR:      cidr,
					Interface: iface.Name,
					IP:        ifaceAddrV.IP.String(),
					MAC:       iface.HardwareAddr.String(),
					IsIPv4:    isIPv4,
				})
			}
		}
	}

	if len(segments) == 0 {
		return nil, errors.New("未找到可用的网络段")
	}

	return segments, nil
}
