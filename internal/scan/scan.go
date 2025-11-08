package scan

import (
	"github.com/fppx/attacker/internal/domain/scan/service"
	"github.com/fppx/attacker/internal/domain/scan/value"
)

var scanService service.ScanService = service.NewScanService()

// Scan 执行网络扫描
func Scan(cidr string) ([]value.IpMac, error) {
	return scanService.Scan(cidr)
}
