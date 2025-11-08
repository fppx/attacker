package service

import "github.com/fppx/attacker/internal/domain/scan/value"

type ScanService interface {
	Scan(cidr string) ([]value.IpMac, error)
}
