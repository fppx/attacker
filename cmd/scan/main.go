package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fppx/attacker/internal/domain/scan/entity"
	"github.com/fppx/attacker/internal/domain/scan/value"
	"github.com/fppx/attacker/internal/scan"
)

// maxInt 返回两个整数中的较大值
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// calculateColumnWidths 计算列宽
func calculateColumnWidths(segments []*value.NetworkSegment) (int, int, int, int) {
	// 最小宽度
	minIndexWidth := 5
	minInterfaceWidth := 8
	minIPWidth := 7
	minMACWidth := 10

	// 计算实际最大宽度
	maxIndexWidth := minIndexWidth
	maxInterfaceWidth := minInterfaceWidth
	maxIPWidth := minIPWidth
	maxMACWidth := minMACWidth

	for i, seg := range segments {
		maxIndexWidth = maxInt(maxIndexWidth, len(strconv.Itoa(i+1)))
		maxInterfaceWidth = maxInt(maxInterfaceWidth, len(seg.Interface))
		maxIPWidth = maxInt(maxIPWidth, len(seg.IP))
		maxMACWidth = maxInt(maxMACWidth, len(seg.MAC))
	}

	// 确保至少等于标题宽度
	maxIndexWidth = maxInt(maxIndexWidth, len("序号"))
	maxInterfaceWidth = maxInt(maxInterfaceWidth, len("网卡名称"))
	maxIPWidth = maxInt(maxIPWidth, len("IP地址"))
	maxMACWidth = maxInt(maxMACWidth, len("MAC地址"))

	return maxIndexWidth, maxInterfaceWidth, maxIPWidth, maxMACWidth
}

// calculateResultColumnWidths 计算扫描结果列宽
func calculateResultColumnWidths(results []value.IpMac) (int, int) {
	minIPWidth := 7
	minMACWidth := 10

	maxIPWidth := minIPWidth
	maxMACWidth := minMACWidth

	for _, result := range results {
		maxIPWidth = maxInt(maxIPWidth, len(result.IP))
		maxMACWidth = maxInt(maxMACWidth, len(result.MAC))
	}

	// 确保至少等于标题宽度
	maxIPWidth = maxInt(maxIPWidth, len("IP地址"))
	maxMACWidth = maxInt(maxMACWidth, len("MAC地址"))

	return maxIPWidth, maxMACWidth
}

func main() {
	var cidr string

	// 如果未传入 CIDR，则列出所有可用网段供用户选择
	if len(os.Args) < 2 {
		segments, err := entity.GetAllAvailableSegments()
		if err != nil {
			fmt.Printf("获取可用网段失败: %v\n", err)
			fmt.Println("用法: scan <CIDR>    例如: scan 192.168.1.0/24 或 scan 2001:db8::/64")
			return
		}

		// 计算列宽
		indexWidth, interfaceWidth, ipWidth, macWidth := calculateColumnWidths(segments)
		typeWidth := 4 // 类型固定为 "IPv4" 或 "IPv6"

		// 计算总宽度
		totalWidth := indexWidth + interfaceWidth + ipWidth + macWidth + typeWidth + 12 // 12 是列之间的空格数

		// 显示可用网段列表
		fmt.Println("检测到以下可用网段，请选择要扫描的网段:")
		fmt.Println(strings.Repeat("-", totalWidth))
		fmt.Printf("%-*s %-*s %-*s %-*s %-*s\n",
			indexWidth, "序号",
			interfaceWidth, "网卡名称",
			ipWidth, "IP地址",
			macWidth, "MAC地址",
			typeWidth, "类型")
		fmt.Println(strings.Repeat("-", totalWidth))

		for i, seg := range segments {
			ipType := "IPv6"
			if seg.IsIPv4 {
				ipType = "IPv4"
			}
			fmt.Printf("%-*d %-*s %-*s %-*s %-*s\n",
				indexWidth, i+1,
				interfaceWidth, seg.Interface,
				ipWidth, seg.IP,
				macWidth, seg.MAC,
				typeWidth, ipType)
		}
		fmt.Println(strings.Repeat("-", totalWidth))

		// 读取用户输入
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("请输入序号 (1-", len(segments), "): ")
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("读取输入失败: %v\n", err)
				return
			}

			input = strings.TrimSpace(input)
			choice, err := strconv.Atoi(input)
			if err != nil || choice < 1 || choice > len(segments) {
				fmt.Printf("无效的序号，请输入 1-%d 之间的数字\n", len(segments))
				continue
			}

			cidr = segments[choice-1].CIDR
			fmt.Printf("\n已选择网段: %s (网卡: %s, IP: %s)\n\n", cidr, segments[choice-1].Interface, segments[choice-1].IP)
			break
		}
	} else {
		cidr = os.Args[1]
	}

	// 执行扫描
	results, err := scan.Scan(cidr)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		return
	}

	// 显示结果
	if len(results) == 0 {
		fmt.Println("未发现任何设备")
		return
	}

	// 计算列宽
	ipWidth, macWidth := calculateResultColumnWidths(results)
	totalWidth := ipWidth + macWidth + 3 // 3 是列之间的空格数

	fmt.Println("扫描结果:")
	fmt.Println(strings.Repeat("-", totalWidth))
	fmt.Printf("%-*s %-*s %-*s %-*s\n", ipWidth, "IP地址", macWidth, "MAC地址", ipWidth, "请求者IP", macWidth, "请求者MAC")
	fmt.Println(strings.Repeat("-", totalWidth))
	for _, result := range results {
		fmt.Printf("%-*s %-*s %-*s %-*s\n", ipWidth, result.IP, macWidth, result.MAC, ipWidth, result.ReqIp, macWidth, result.ReqMac)
	}
	fmt.Println(strings.Repeat("-", totalWidth))
	fmt.Printf("共发现 %d 个设备\n", len(results))
}
